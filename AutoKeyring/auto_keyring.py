#!/usr/bin/env python3
import contextlib
import ctypes
import json
import os
import shutil
import subprocess
import sys
import time
import tomllib

from base64 import b64encode
from hashlib import sha256
import gi
gi.require_version(namespace='Gio', version='2.0')
from gi.repository import Gio, GLib
from pathlib import Path
from typing import TYPE_CHECKING, Any, Generator


import secretstorage

# tomli_w imported as needed in Config.write_default_config()

if TYPE_CHECKING:
    from gi.overrides.GLib import Variant
    from subprocess import CompletedProcess
    from jeepney.io.blocking import DBusConnection
    from secretstorage.collection import Collection
    from secretstorage.dhcrypto import Session as SecretServiceSession


ClevisSettingsType = dict[
    str, str | dict[str, str | int | list[str | int | None]] | None
]
ConfigType = dict[str, str | int | ClevisSettingsType]

app_name = "AutoKeyring"
app_name_lower = app_name.lower()

def run_process(args: list[str], **kwargs) -> Any | None:
    try:
        return subprocess.run(args, **kwargs)
    except subprocess.CalledProcessError as e:
        print(f"We seem to have run into a problem executing this subprocess.\n Process returncode: {e.returncode}, command sent: {e.cmd},\nerror response: {e.stderr}, \n output (if any): {e.output}\n")

def wait_for_valid_session(sleep_time: int = 30) -> "LogindSession | None":
    """Wait for a valid session. This function will loop indefinitely until a valid session is found."""
    while True:
        s = LogindSession.get_active_session()
        if s and s.is_valid_session():
            return s
        time.sleep(sleep_time)

def wait_for_user():
    time.sleep(360)  # wait for a user who uses autokeyring
    main()

def handle_file_operations(file_path: Path, write_content: bytes, file_description: str = 'file', modhex: str = "0o400") -> None:
    if file_path.exists() and file_path.stat().st_size > 0:
        os.rename(file_path, file_path.with_suffix(".old"))
    file_path.touch()
    file_path.write_bytes(write_content)
    if file_path.stat().st_size > 0:
        file_path.chmod(modhex)
        print(f"A new {file_description} was created at {str(file_path)}")
    else:
        file_path.unlink(missing_ok=True)
        raise ValueError(f"Failed to create a new {file_description}")

def get_xdg_dirs() -> tuple[Path, Path]:
    """Get the XDG directories.

    Returns:
        tuple[str, str]: The XDG directories.
    """
    xdg_data_home = Path(os.getenv("XDG_DATA_HOME", "~/.local/share"))
    xdg_config_home = Path(os.getenv("XDG_CONFIG_HOME", "~/.config"))
    return xdg_data_home.expanduser(), xdg_config_home.expanduser()

class LogindSession:
    def __init__(self, session_dict):
        for key, value in session_dict.items():
            setattr(self, key, value)

    @classmethod
    def parse_sessions_variants(cls, sessions_variant: Variant) -> list["LogindSession"]:
        session_dicts = []
        for session in sessions_variant.unpack()[0]:
            session_id, user_id, user_name, seat_id, object_path = session
            session_info: Variant = bus.call_sync(
                'org.freedesktop.login1',
                object_path,
                'org.freedesktop.DBus.Properties',
                'GetAll',
                GLib.Variant('(s)', ('org.freedesktop.login1.Session',)),
                GLib.VariantType('(a{sv})'),
                Gio.DBusCallFlags.NONE,
                -1,
                None
            )

            properties = {k: v.unpack() if isinstance(v, GLib.Variant) else v for k, v in session_info.unpack()[0].items()}
            properties.update({'session_id': session_id, 'uid': user_id, 'user_name': user_name, 'seat_id': seat_id})
            session_dicts.append(cls(properties))

        return session_dicts

    @classmethod
    def from_logins(cls) -> list["LogindSession"]:
        bus = Gio.bus_get_sync(Gio.BusType.SYSTEM, None)

        return cls.parse_sessions_variants(bus.call_sync(
            'org.freedesktop.login1',
            '/org/freedesktop/login1',
            'org.freedesktop.login1.Manager',
            'ListSessions',
            None,
            GLib.VariantType('(a(susso))'),
            Gio.DBusCallFlags.NONE,
            -1,
            None
        ))

    def __repr__(self) -> str:
        return f"LogindSession(session_id={self.session_id}, uid={self.uid}, user_name={self.user_name}, seat_id={self.seat_id})"

    def is_valid_session(self) -> bool:
        return getattr(self, 'uid', None) is not None and 1000 <= self.uid < 65534


class ConfigValidator:
    def __init__(self, config: ConfigType) -> None:
        self.config = config
        self.valid: bool = self.is_valid(config)

    def _valid_sss_config(self, clevis: ClevisSettingsType, pt: set[str] | str, t: int) -> bool:
        valid_pin_types = {"tpm2", "tang", "yubikey"}
        if not pt.issubset(valid_pin_types):
            return False
        if "tang" not in pt and (t > len(pt)) or len(pt) == 1:
            return False
        urls = clevis.get("tang", {}).get("url", [])
        if not urls or (t > len(pt) + len(urls)):
            return False
        for p in pt:
            func = getattr(self, f"_valid_{p}_config")
            if not func(clevis.get(p, {})):
                return False
        return True

    @staticmethod
    def _valid_yubikey_config(slots: int | None) -> bool:
        return slots and slots in {1,2}

    @staticmethod
    def _valid_tang_config(t_config: dict[str, set[str] | str]) -> bool:
        for key in {"thp", "adv", "url"}:
            value = t_config.get(key)
            if key == 'url':
                if not value:
                    return False
            elif not isinstance(value, set) or not all(isinstance(x, str) for x in value):
                return False
        return (
            "adv_obj" not in t_config
            or isinstance(t_config["adv_obj"], str)
            and "adv" not in t_config
        )

    @staticmethod
    def _valid_tpm2_config(tpm_config: dict[str, str | set[int | str]] | None = None) -> bool:
        tpm_config = tpm_config or {}
        if not tpm_config:
            return True
        if (hash := tpm_config.get("hash")) and hash not in {"sha256", "sha384", "sha512", "sm3_256"}:
            return False
        if (algo := tpm_config.get("algo")) and algo not in {"ecc", "rsa", "symcipher", "keyedhash"}:
            return False
        if (pcr_bank := tpm_config.get("pcr_bank")) and pcr_bank not in {"sha1", "sha256"}:
            return False
        if pcr_ids := tpm_config.get("pcr_ids"):
            if not isinstance(pcr_ids, set) or any(not isinstance(id, (str, int)) or int(id) not in range(31) for id in pcr_ids):
                return False
        return True

    def is_valid(self, config: ConfigType) -> bool:
        clevis = config.get("clevis_settings", {"binding": "tpm2"})
        try:
            match clevis:
                case {"binding": "sss", "sss": sss} if "threshold" in sss and "pin_types" in sss and sss["threshold"] > 0:
                    return self._valid_sss_config(clevis, sss["pin_types"], sss["threshold"])
                case {"binding": "yubikey", "yubikey": yubikey} if "slots" in yubikey:
                    return self._valid_yubikey_config(yubikey["slots"])
                case {"binding": "tang", "tang": tang} if "url" in tang:
                    return self._valid_tang_config(clevis.get("tang", {}))
                case {"binding": "tpm2"}:
                    return self._valid_tpm2_config(clevis.get("tpm2", {}))
                case _:
                    print(f"Unsupported binding type or missing required fields in {clevis}")
                    return False
        except (ValueError, KeyError) as e:
            print(f"Configuration validation error: {e}")
            return False

class Config:
    def __init__(self, user: str) -> None:
        self.user: str = user
        # let's get all of the paths we need
        self.path_dict = self.get_paths()
        for key, path in self.path_dict.values():
            self.ensure_path(key, path)
            setattr(self, key, path)
        self.config_path = self.xdg_config_home / f"{app_name}/config.toml"
        self._default_encrypted_path = self.data_home / f"{app_name}/key.jwe"
        if not self.config_path.exists():
            self.config_path.parent.mkdir(parents=True, exist_ok=True)
            self.config = self.write_default_config()
        self.config = self.import_config()

    @staticmethod
    def ensure_path(name: str, path: Path) -> None:
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            if not path.exists():
                path.touch()
            if path.is_file():
                path.chmod(0o600)
        except PermissionError as e:
            print(f"Permission error: {e}")
            raise SystemExit(1) from e
        except OSError as e:
            print(f"OS error: {e}")
    @property
    def default_config(self) -> dict:
        return {
            "encrypted_path": str(self._default_encrypted_path),
            "clevis_settings": {"binding": "tpm2"},
        }

    def write_default_config(self) -> dict:
        import tomli_w
        with self.config_path.open("wb") as f:
            tomli_w.dump(self.default_config, f)
        return self.default_config

    def import_config(self) -> dict:
        with self.config_path.open("rb") as f:
            config = tomllib.load(f)
        return self.correct_types(config)

    def correct_types(self, config: dict) -> dict:
        if "encrypted_path" in config:
            config["encrypted_path"] = Path(config["encrypted_path"])
        if "clevis_settings" in config and isinstance(config["clevis_settings"], dict):
            for k, v in config["clevis_settings"].items():
                if k != "binding":
                    config["clevis_settings"][k] = self._correct_nested_config(v)
        return config

    def _correct_nested_config(self, value: Any) -> ConfigType:
        if isinstance(value, dict):
            return {k: self._correct_nested_config(v) for k, v in value.items()}
        elif isinstance(value, list):
            return {self._correct_nested_config(item) for item in value}
        elif isinstance(value, str) and value.isdigit():
            return int(value)
        else:
            return value

    def get_paths(self) -> dict[str, Path]:
        data_home, config_home = get_xdg_dirs()
        return {
            "data_home": data_home,
            "config_home": config_home,
            "home": Path.home(),
            "config_path": config_home / f"{app_name}/config.toml",
            "encrypted_path": Path(self.config.get("encrypted_path", data_home / f"{app_name}/key.jwe")),
        }


class ClevisCommand:
    def __init__(self, config: Config) -> None:
        self.config: Config = config
        self.conf: ConfigType = config.config
        self._unmod_conf: ConfigType = self.conf.copy()

        self.key_file: Path = self.conf['encrypted_path']
        self.settings: ClevisSettingsType = self.conf.get('clevis_settings', {"binding": "tpm2"})
        self.clevis_exec: str = shutil.which("clevis") or "/usr/bin/clevis"
        self._encrypt_args, self._decrypt_args = self._get_cmd_args()

    @property
    def encrypt_cmd(self) -> list[str]:
        return self._encrypt_args

    @property
    def decrypt_cmd(self) -> list[str]:
        return self._decrypt_args

    @staticmethod
    def _substitute_clevis_items(config: ConfigType) -> ConfigType:
        """Substitute the keys in the config."""
        subs: dict[str, str] = {"threshold": "t", "pin_types": "pins", "algo": "key", "adv_obj": "adv"}

        def substitute(d) -> dict[str, Any]:
            return {subs.get(k, k): substitute(v) if isinstance(v, dict) else (list(v) if isinstance(v, set) else v) for k, v in d.items()}

        return substitute(config)

    @staticmethod
    def _zip_sss_tang_settings(tang_settings: dict[str, set[str] | str]) -> Any | list[Any]:
        keys = set(tang_settings.keys())
        max_length = len(tang_settings['url'])
        tang_configs = []
        for _ in range(max_length):
            config = {}
            with contextlib.suppress((KeyError, StopIteration)):
                for key in keys:
                    if not config[key]:
                        continue
                    config[key] = next(iter(tang_settings[key]), None)
            tang_configs.append(config)
        if len(tang_configs) == 1:
            tang_configs = tang_configs[0]
        return tang_configs

    def _construct_clevis_args(self, clevis: ClevisSettingsType) -> list[str] | None = None:
        """Set the clevis settings."""
        clevis = clevis or self.settings
        binding: str = clevis["binding"]
        subbed_clevis = self._substitute_clevis_items(clevis)
        binding_settings = subbed_clevis.get(binding, {})

        if binding == 'sss':
            pin_settings = {binding: subbed_clevis.get(binding, {}) for binding in subbed_clevis['sss']['pins']}
            json_payload = {}

            for pin in pin_settings:
                if pin == 'tang':
                    tang_settings = {k:v for k,v in pin_settings.get("tang", {}) if v}
                    json_payload['tang'] = self._zip_sss_tang_settings(tang_settings)
                else:
                    json_payload[pin] = subbed_clevis.get(pin, {})
        else:
            binding_settings = subbed_clevis.get(binding, {})
            json_payload = binding_settings

        return [binding, json.dumps(json_payload, separators=(',', ':'))]

    def _get_cmd_args(self, clevis: ClevisSettingsType = None) -> tuple[list[str], list[str]]:
        """Get the clevis command."""
        decrypt = [self.clevis_exec, 'decrypt']
        clevis = clevis or self.settings
        encrypt_args: list[str] = self._construct_clevis_args(clevis)
        return [str(self.clevis_exec), 'encrypt', '-y', *encrypt_args], decrypt


class KeyStore:
    def __init__(self, config: Config, logindsession: LogindSession, generate_new_key: bool = False) -> None:
        self.config: Config = config
        self.conf: ConfigType = config.config
        self.login: LogindSession = logindsession
        self.key_file: Path = self.conf['encrypted_path']
        self.command: ClevisCommand = ClevisCommand(config)

        if generate_new_key:
            self.gen_cipher_key()

    @staticmethod
    def zeroize(secret: bytearray | bytes) -> None:
        """Zeroize the bytearray using ctypes."""
        buffer = (ctypes.c_char * len(secret)).from_buffer(secret)
        ctypes.memset(buffer, 0, len(secret))
        del buffer # totally unnecessary, but ... paranoia.

    @property
    def subproc_failure(self, e: subprocess.CalledProcessError) -> None:
        raise e(f'Failed to run the subprocess. Process returncode: {e.returncode}, command sent: {e.cmd.decode()},\nerror response: {e.stderr.decode()}, \n output (if any): {e.output.decode()}\n')

    @property
    def salt(self) -> bytes | None:
        base = bytearray(b64encode(self.login.user + self.login.uid + self.key_file.stat().st_size))
        combined = self.__the_fig_loves_the_pepper__.extend(base)
        return sha256(b64encode(combined)).digest()

    @property
    def __the_fig_loves_the_pepper__(self) -> bytearray:
        return bytearray(f"This adds a smidgen of obfuscation, but not none... {sys._getframe().f_code.co_name}")

    @contextlib.contextmanager
    def seal_secret(self, secret: bytearray, args: list[str] = None, **kwargs) -> Generator[bytes, Any, None]:
        args = args or self.command.encrypt_cmd
        kwargs = {"check": True, "timeout": 15, **kwargs, "input": secret}
        try:
            yield run_process(args, kwargs)
        except subprocess.CalledProcessError as e:
            self.subproc_failure(e)

        finally:
            if secret:
                self.zeroize(secret)

    @contextlib.contextmanager
    def unseal_secret(self, salt = None, args: list[str] = None, **kwargs) -> Generator[bytes, Any, None]:
        args = args or self.command.decrypt_cmd
        try:
            key = bytearray(self.key_file.read_bytes())
            kwargs = {"check": True, "timeout": 15, "stdout": subprocess.PIPE, "input": key, **kwargs}
            opened = bytearray(run_process(args, kwargs).stdout)
            yield b64encode(self.__the_fig_loves_the_pepper__.extend(opened).extend(self.salt))
        except subprocess.CalledProcessError as e:
            self.subproc_failure(e)
        finally:
            if opened:
                self.zeroize(opened)

    @contextlib.contextmanager
    def gen_secret(self) -> Generator[bytearray, Any, None]:
        try:
            _secret = bytearray(os.urandom(32))
            yield _secret
        except OSError as e:
            raise OSError(f"Failed to generate a secret: {e}") from e
        finally:
            if _secret:
                self.zeroize(_secret)

    def gen_cipher_key(self) -> None:
        with self.gen_secret() as secret, self.seal_secret(secret) as sealed:
            handle_file_operations(self.key_file, sealed, "key file")
        if secret:
            self.zeroize(secret)

class AutoKeyring:
    """AutoKeyring class."""

    def __init__(self, config: Config = None, gen_key: bool = False, gen_keyring: bool = False) -> None:
        """Initialize the AutoKeyring class."""
        self.config: Config = config or Config(LogindSession.get_active_session().user)
        self.conf: ConfigType = config.config
        self.keystore: KeyStore = KeyStore(config)

        self.connection: DBusConnection = secretstorage.dbus_init()
        self.keyring: Collection = self._get_keyring()
        self.label: str = self.keyring.get_label()

    def _get_keyring(self) -> Collection:
        """Get the keyring."""
        try:
            return secretstorage.get_collection_by_alias(self.connection, "autokeyring")
        except secretstorage.exceptions.ItemNotFoundException:
            return secretstorage.get_default_collection(self.connection)
        except secretstorage.exceptions.SecretServiceNotAvailableException as e:
            print("Secret Service API not available. Exiting.\n Error: {e}")
            raise SystemExit(1) from e

    @property
    def unlocked(self) -> bool:
        """Check if the keyring is unlocked."""
        return not self.keyring.is_locked()

    @property
    def locked(self) -> bool:
        """Check if the keyring is locked."""
        return self.keyring.is_locked()

    def unlock(self) -> bool:
        """Unlock the keyring."""
        if self.unlocked:
            return True

    @contextlib.contextmanager
    def get_secret_session(
        self, connection: DBusConnection = None
    ) -> SecretServiceSession:
        """Get the secret."""
        try:
            connection = connection or self.connection
            session = secretstorage.utils.open_session(
            self.connection
        )
            with self.keyring.unseal_secret() as plaintext:
                yield secretstorage.utils.format_secret(session, plaintext_secret)

        except secretstorage.exceptions.SecretServiceNotAvailableException as e:
            print("Secret Service API not available. Exiting.\n Error: {e}")
            raise SystemExit(1) from e
        finally:
            session.close()


def main() -> SystemExit:
    # We use the session to get the user id; we don't use pwd.getpwuid() because it relies on environment variables that could be hijacked
    s: LogindSession = wait_for_valid_session()
    config = Config(s.user)
    conf = config.config
    if generate_keyring:
        # generate the keyring

    if not conf.get("encrypted_path", None):
        wait_for_user()

    if not conf["encrypted_path"].exists():
        wait_for_user()

    keyring = AutoKeyring(config)
    if keyring.unlocked:
        return SystemExit(0)  # if it's unlocked, we can exit


if __name__ == "__main__":
    main()
