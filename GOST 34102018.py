from __future__ import annotations

import os
import json
import hashlib
import datetime
from dataclasses import dataclass, field
from typing import Optional

import gostcrypto.gostsignature as gostsign
import gostcrypto.gosthash as goshash


# ---------------------------------------------------------------------------
# Параметры эллиптических кривых (ГОСТ Р 34.10-2018 / Р 1323565.1.024-2019)
# ---------------------------------------------------------------------------

CURVES = gostsign.CURVES_R_1323565_1_024_2019

CURVE_MAP = {
    256: {
        "id-tc26-gost-3410-2012-256-paramSetA": "ТС26 256-A (рекомендован КС1/КС2)",
        "id-tc26-gost-3410-2012-256-paramSetB": "ТС26 256-B",
        "id-tc26-gost-3410-2012-256-paramSetC": "ТС26 256-C",
        "id-tc26-gost-3410-2012-256-paramSetD": "ТС26 256-D",
    },
    512: {
        "id-tc26-gost-3410-12-512-paramSetA":   "ТС26 512-A",
        "id-tc26-gost-3410-12-512-paramSetB":   "ТС26 512-B (рекомендован КВ1/КВ2)",
        "id-tc26-gost-3410-2012-512-paramSetC": "ТС26 512-C",
    },
}

DEFAULT_CURVE = {
    256: "id-tc26-gost-3410-2012-256-paramSetA",
    512: "id-tc26-gost-3410-12-512-paramSetB",
}

HASH_ALG = {256: "streebog256", 512: "streebog512"}
MODE_FLAG = {256: gostsign.MODE_256, 512: gostsign.MODE_512}


# ---------------------------------------------------------------------------
# Вспомогательные типы
# ---------------------------------------------------------------------------

@dataclass
class KeyPair:

    """Пара ключей ГОСТ Р 34.10-2018."""
    private_key: bytearray
    public_key: bytearray
    mode: int        
    curve_id: str

    @property
    def private_hex(self) -> str:
        return self.private_key.hex()

    @property
    def public_hex(self) -> str:
        return self.public_key.hex()

    def to_dict(self) -> dict:
        return {
            "mode": self.mode,
            "curve_id": self.curve_id,
            "private_key": self.private_hex,
            "public_key": self.public_hex,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "KeyPair":
        return cls(
            private_key=bytearray.fromhex(d["private_key"]),
            public_key=bytearray.fromhex(d["public_key"]),
            mode=d["mode"],
            curve_id=d["curve_id"],
        )


@dataclass
class SignatureResult:
    signature: bytearray
    digest: bytearray
    mode: int
    curve_id: str
    hash_alg: str
    timestamp: str = field(default_factory=lambda: datetime.datetime.utcnow().isoformat())

    @property
    def signature_hex(self) -> str:
        return self.signature.hex()

    @property
    def digest_hex(self) -> str:
        return self.digest.hex()

    def to_dict(self) -> dict:
        return {
            "mode": self.mode,
            "curve_id": self.curve_id,
            "hash_alg": self.hash_alg,
            "timestamp": self.timestamp,
            "digest": self.digest_hex,
            "signature": self.signature_hex,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "SignatureResult":
        return cls(
            signature=bytearray.fromhex(d["signature"]),
            digest=bytearray.fromhex(d["digest"]),
            mode=d["mode"],
            curve_id=d["curve_id"],
            hash_alg=d["hash_alg"],
            timestamp=d.get("timestamp", ""),
        )


# ---------------------------------------------------------------------------
# Основной класс
# ---------------------------------------------------------------------------

class GOST34102018:
    """
    Электронная цифровая подпись ГОСТ Р 34.10-2018.

    Пример использования::

        gost = GOST34102018(mode=256)
        keys = gost.generate_keys()
        sig  = gost.sign(b"Мой документ", keys.private_key)
        ok   = gost.verify(b"Мой документ", sig.signature, keys.public_key)
    """

    def __init__(self, mode: int = 256, curve_id: Optional[str] = None):
        """
        Параметры:
            mode     — 256 или 512 (размер ключа в битах).
            curve_id — идентификатор кривой; если None — выбирается по умолчанию.
        """
        if mode not in (256, 512):
            raise ValueError("mode должен быть 256 или 512")

        self.mode = mode
        self.curve_id = curve_id or DEFAULT_CURVE[mode]

        if self.curve_id not in CURVES:
            raise ValueError(f"Неизвестная кривая: {self.curve_id}")

        self._curve_params = CURVES[self.curve_id]
        self._mode_flag = MODE_FLAG[mode]
        self._hash_alg = HASH_ALG[mode]
        self._key_size = mode // 8   # байт
        self._signer = gostsign.new(self._mode_flag, self._curve_params)

    # ------------------------------------------------------------------
    # Генерация ключей
    # ------------------------------------------------------------------

    def generate_keys(self) -> KeyPair:
        """
        Генерация пары ключей.

        Приватный ключ — случайное число из [1, q-1], где q — порядок
        группы точек кривой. Публичный ключ вычисляется как Q = d·P.

        Возвращает: KeyPair
        """

        private_key = bytearray(os.urandom(self._key_size))
        public_key = self._signer.public_key_generate(private_key)
        return KeyPair(
            private_key=private_key,
            public_key=bytearray(public_key),
            mode=self.mode,
            curve_id=self.curve_id,
        )

    # ------------------------------------------------------------------
    # Хэширование
    # ------------------------------------------------------------------

    def hash_message(self, message: bytes) -> bytearray:
        """
        Вычисление хэша сообщения алгоритмом «Стрибог».

        Параметры:
            message — произвольное сообщение в байтах.

        Возвращает: хэш-значение (bytearray, 32 или 64 байта).
        """
        hasher = goshash.new(self._hash_alg, data=bytearray(message))
        return bytearray(hasher.digest())

    # ------------------------------------------------------------------
    # Формирование подписи
    # ------------------------------------------------------------------

    def sign(self, message: bytes, private_key: bytearray) -> SignatureResult:
        """
        Формирование электронной цифровой подписи.

            1. Вычислить хэш-значение e = H(M).
            2. Сгенерировать случайное k ∈ [1, q-1].
            3. Вычислить точку C = k·P → r = xC mod q.
            4. Вычислить s = (r·d + k·e) mod q.
            5. Подпись: (r, s).

        Параметры:
            message     — подписываемое сообщение.
            private_key — приватный ключ (bytearray).

        Возвращает: SignatureResult
        """
        digest = self.hash_message(message)
        signature = bytearray(self._signer.sign(private_key, digest))
        return SignatureResult(
            signature=signature,
            digest=digest,
            mode=self.mode,
            curve_id=self.curve_id,
            hash_alg=self._hash_alg,
        )

    # ------------------------------------------------------------------
    # Проверка подписи
    # ------------------------------------------------------------------

    def verify(
        self,
        message: bytes,
        signature: bytearray,
        public_key: bytearray,
    ) -> bool:
        """
        Проверка электронной цифровой подписи.

            1. Вычислить хэш-значение e = H(M).
            2. Из подписи извлечь (r, s); проверить r,s ∈ [1, q-1].
            3. v = e^(-1) mod q.
            4. z1 = s·v mod q,  z2 = -r·v mod q.
            5. Вычислить точку A = z1·P + z2·Q → R = xA mod q.
            6. Подпись верна ⟺ R == r.

        Параметры:
            message    — исходное сообщение.
            signature  — подпись (bytearray, 64 или 128 байт).
            public_key — открытый ключ (bytearray).

        Возвращает: True если подпись верна, False иначе.
        """

        digest = self.hash_message(message)
        return bool(self._signer.verify(public_key, digest, signature))

    def verify_from_result(self, message: bytes, sig_result: SignatureResult, public_key: bytearray) -> bool:
        return self.verify(message, sig_result.signature, public_key)

    # ------------------------------------------------------------------
    # Информация
    # ------------------------------------------------------------------

    def info(self) -> str:
        desc = CURVE_MAP.get(self.mode, {}).get(self.curve_id, self.curve_id)
        return (
            f"ГОСТ Р 34.10-2018\n"
            f"  Режим       : {self.mode} бит\n"
            f"  Кривая      : {self.curve_id}\n"
            f"              ({desc})\n"
            f"  Хэш-функция : {self._hash_alg} (ГОСТ Р 34.11-2018 / Стрибог)\n"
            f"  Размер ключа: {self._key_size} байт ({self.mode} бит)\n"
            f"  Размер подп.: {self._key_size * 2} байт ({self.mode * 2} бит)\n"
        )


# ---------------------------------------------------------------------------
# Утилиты сохранения / загрузки
# ---------------------------------------------------------------------------

def save_keys(keys: KeyPair, path: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(keys.to_dict(), f, ensure_ascii=False, indent=2)
    print(f"[V] Ключи сохранены → {path}")


def load_keys(path: str) -> KeyPair:
    with open(path, "r", encoding="utf-8") as f:
        return KeyPair.from_dict(json.load(f))


def save_signature(sig: SignatureResult, path: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(sig.to_dict(), f, ensure_ascii=False, indent=2)
    print(f"[V] Подпись сохранена → {path}")


def load_signature(path: str) -> SignatureResult:
    with open(path, "r", encoding="utf-8") as f:
        return SignatureResult.from_dict(json.load(f))


# ---------------------------------------------------------------------------
# Демонстрация
# ---------------------------------------------------------------------------

def _separator(title: str = "") -> None:
    line = "─" * 60
    if title:
        print(f"\n{line}")
        print(f"  {title}")
        print(line)
    else:
        print(line)


def demo():
    print("=" * 60)
    print("  ЭЦП по ГОСТ Р 34.10-2018 — демонстрация")
    print("=" * 60)

    # --- 1. Режим 256 бит -------------------------------------------
    _separator("РЕЖИМ 256 БИТ")

    gost256 = GOST34102018(mode=256)
    print(gost256.info())

    print("[1] Генерация ключей...")
    keys256 = gost256.generate_keys()
    print(f"    Приватный ключ ({len(keys256.private_key)} байт):\n"
          f"      {keys256.private_hex}")
    print(f"    Открытый ключ  ({len(keys256.public_key)} байт):\n"
          f"      {keys256.public_hex}")

    message = "Привет, ГОСТ! Это тестовое сообщение для подписи.".encode("utf-8")
    print(f"\n[2] Сообщение ({len(message)} байт): «{message.decode()}»")

    print("\n[3] Хэширование (Стрибог-256)...")
    digest = gost256.hash_message(message)
    print(f"    Хэш ({len(digest)} байт): {digest.hex()}")

    print("\n[4] Формирование подписи...")
    sig256 = gost256.sign(message, keys256.private_key)
    print(f"    Подпись ({len(sig256.signature)} байт):\n"
          f"      {sig256.signature_hex}")
    print(f"    Метка времени: {sig256.timestamp}")

    print("\n[5] Проверка подписи (корректное сообщение)...")
    ok = gost256.verify(message, sig256.signature, keys256.public_key)
    status = "ПОДПИСЬ ВЕРНА" if ok else "ПОДПИСЬ НЕВЕРНА"
    print(f"    Результат: {status}")

    print("\n[6] Проверка подписи (изменённое сообщение)...")
    tampered = message + " [фальсификация]".encode("utf-8")
    ok_tampered = gost256.verify(tampered, sig256.signature, keys256.public_key)
    status2 = "Верна" if ok_tampered else "НЕВЕРНА (фальсификация обнаружена!)"
    print(f"    Результат: {status2}")

    print("\n[7] Проверка подписи (чужой ключ)...")
    other_keys = gost256.generate_keys()
    ok_wrong_key = gost256.verify(message, sig256.signature, other_keys.public_key)
    status3 = "Верна" if ok_wrong_key else "НЕВЕРНА (чужой ключ обнаружен!)"
    print(f"    Результат: {status3}")

    # --- 2. Режим 512 бит -------------------------------------------
    _separator("РЕЖИМ 512 БИТ")

    gost512 = GOST34102018(mode=512)
    print(gost512.info())

    print("[1] Генерация ключей...")
    keys512 = gost512.generate_keys()
    print(f"    Приватный ключ ({len(keys512.private_key)} байт): {keys512.private_hex[:32]}…")
    print(f"    Открытый ключ  ({len(keys512.public_key)} байт): {keys512.public_hex[:32]}…")

    print("\n[2] Формирование подписи (Стрибог-512)...")
    sig512 = gost512.sign(message, keys512.private_key)
    print(f"    Хэш ({len(sig512.digest)} байт):    {sig512.digest_hex[:32]}…")
    print(f"    Подпись ({len(sig512.signature)} байт): {sig512.signature_hex[:32]}…")

    print("\n[3] Проверка подписи...")
    ok512 = gost512.verify(message, sig512.signature, keys512.public_key)
    print(f"    Результат: {'ПОДПИСЬ ВЕРНА' if ok512 else 'НЕВЕРНА'}")

    # --- 3. Сохранение и загрузка -----------------------------------
    _separator("СОХРАНЕНИЕ И ЗАГРУЗКА")

    save_keys(keys256, "gost_keys.json")
    loaded_keys = load_keys("gost_keys.json")
    assert loaded_keys.private_hex == keys256.private_hex
    print("Ключи успешно загружены и совпадают")

    save_signature(sig256, "gost_sig.json")
    loaded_sig = load_signature("gost_sig.json")
    assert loaded_sig.signature_hex == sig256.signature_hex
    print("Подпись успешно загружена и совпадает")

    ok_loaded = gost256.verify(message, loaded_sig.signature, loaded_keys.public_key)
    print(f"Проверка после загрузки из файла: {'ВЕРНА' if ok_loaded else 'НЕВЕРНА'}")

    # --- 4. Итог ----------------------------------------------------
    _separator("ИТОГИ ТЕСТИРОВАНИЯ")
    results = {
        "256-бит, оригинал":      ok,
        "256-бит, фальсификация": not ok_tampered,
        "256-бит, чужой ключ":    not ok_wrong_key,
        "512-бит, оригинал":      ok512,
        "сохранение/загрузка":    ok_loaded,
    }
    all_pass = all(results.values())
    for name, passed in results.items():
        print(f"  {'V' if passed else 'X'} {name}")
    print()
    print(f"  {'[ВСЕ ТЕСТЫ ПРОЙДЕНЫ]' if all_pass else '[ЕСТЬ ОШИБКИ]'}")
    _separator()


# ---------------------------------------------------------------------------
# Точка входа
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    demo()