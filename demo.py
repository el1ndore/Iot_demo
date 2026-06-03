import sys
import time

if sys.platform == 'win32':
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')

from colors import C, banner, info, ok, warn, hdr, field
from pki import build_pki, cert_info
from device import IoTDevice
from gateway import IoTGateway
from attacker import Attacker
from benchmark import run_benchmark


def pause():
    input(f"\n{C.DIM}[Нажмите Enter для продолжения]{C.RST} ")


def _connected_pair(pki, serial=0xA5F3B201):
    device = IoTDevice(serial=serial, ca_cert=pki['ca_cert'],
                       device_cert=pki['device_cert'],
                       device_key=pki['device_key'])
    gateway = IoTGateway(ca_cert=pki['ca_cert'],
                         gateway_cert=pki['gateway_cert'],
                         gateway_key=pki['gateway_key'])
    device.handshake(gateway)
    return device, gateway


def scenario_normal(device, gateway):
    banner("СЦЕНАРИЙ 1: ШТАТНАЯ ПЕРЕДАЧА ДАННЫХ")
    info("Устройство измеряет показания и отправляет их шлюзу")
    info("по защищённому каналу AES-128-CCM поверх UDP")
    print()

    for i in range(3):
        hdr(f"--- Передача №{i+1} ---")
        packet = device.create_telemetry_packet()
        time.sleep(0.3)
        gateway.receive_packet(packet)
        time.sleep(0.3)
        print()

    pause()


def scenario_tamper(device, gateway, attacker):
    banner("СЦЕНАРИЙ 2: ПОДМЕНА ПАКЕТА (нарушение целостности)")
    info("Злоумышленник перехватывает пакет и меняет в нём один байт.")
    info("Шифр AES-CCM должен это обнаружить через проверку тега.")
    print()

    hdr("--- Шаг 1: устройство отправляет пакет ---")
    packet = device.create_telemetry_packet()
    time.sleep(0.5)

    hdr("--- Шаг 2: злоумышленник модифицирует пакет ---")
    tampered = attacker.tamper_packet(packet)
    time.sleep(0.5)

    hdr("--- Шаг 3: шлюз получает модифицированный пакет ---")
    gateway.receive_packet(tampered)

    pause()


def scenario_replay(device, gateway, attacker):
    banner("СЦЕНАРИЙ 3: REPLAY-АТАКА")
    info("Злоумышленник перехватывает легитимный пакет")
    info("и пытается отправить его повторно.")
    info("Защита: счётчик сообщений в составе AAD.")
    print()

    hdr("--- Шаг 1: устройство отправляет легитимный пакет ---")
    packet = device.create_telemetry_packet()
    time.sleep(0.3)
    gateway.receive_packet(packet)
    time.sleep(0.5)

    hdr("--- Шаг 2: злоумышленник перехватил пакет и сохранил его ---")
    attacker.capture_packet(packet)
    time.sleep(0.5)

    hdr("--- Шаг 3: устройство отправляет следующее сообщение ---")
    next_packet = device.create_telemetry_packet()
    gateway.receive_packet(next_packet)
    time.sleep(0.5)

    hdr("--- Шаг 4: злоумышленник отправляет старый пакет ---")
    replayed = attacker.replay_last()
    gateway.receive_packet(replayed)

    pause()


def scenario_mitm(pki):
    banner("СЦЕНАРИЙ 4: MITM С ПОДМЕНОЙ СЕРТИФИКАТА")
    info("Злоумышленник пытается выдать себя за шлюз,")
    info("предъявляя устройству самоподписанный сертификат.")
    info("Защита: проверка цепочки доверия до корневого CA.")
    print()

    hdr("--- Шаг 1: устройство подключается к легитимному шлюзу ---")
    _connected_pair(pki)
    time.sleep(0.5)
    print()

    hdr("--- Шаг 2: злоумышленник создаёт поддельный шлюз ---")
    fake = Attacker.create_fake_gateway()
    info("Поддельный сертификат подписан САМ СОБОЙ (не доверенным CA)")
    time.sleep(0.5)
    print()

    victim_device = IoTDevice(serial=0xA5F3B202, ca_cert=pki['ca_cert'],
                              device_cert=pki['device_cert'],
                              device_key=pki['device_key'])

    hdr("--- Шаг 3: устройство пытается подключиться к поддельному шлюзу ---")
    victim_device.handshake(fake)

    pause()


def _show_cert(title, cert):
    c = cert_info(cert)
    ok(title)
    field("субъект:", f"CN={c['cn']}, O=IoT-Demo, C=RU")
    field("издатель:", f"CN={c['issuer']}" +
          ("  (самоподписанный)" if c['self_signed'] else ""))
    field("серийный №:", f"0x{c['serial']:X}")
    field("отпечаток:", f"{c['fingerprint'][:32]}… (SHA-256)")
    field("действует до:", f"{c['not_after']:%Y-%m-%d}")


def init_pki():
    info("Инициализация инфраструктуры открытых ключей (кривая secp256r1)...")
    pki = build_pki()
    _show_cert("Корневой удостоверяющий центр выпущен", pki['ca_cert'])
    _show_cert("Сертификат шлюза выпущен и подписан CA", pki['gateway_cert'])
    _show_cert("Сертификат устройства выпущен и подписан CA", pki['device_cert'])
    return pki


def menu():
    banner("ДЕМОНСТРАЦИЯ ЗАЩИТЫ ДАННЫХ В IoT", char='=')

    pki = init_pki()
    print()

    while True:
        hdr("=" * 60)
        print(f"  {C.BOLD}Выберите сценарий:{C.RST}")
        print(f"  {C.GREEN}1{C.RST}) Штатная передача данных")
        print(f"  {C.YELLOW}2{C.RST}) Подмена пакета (нарушение целостности)")
        print(f"  {C.YELLOW}3{C.RST}) Replay-атака")
        print(f"  {C.YELLOW}4{C.RST}) MITM с подменой сертификата")
        print(f"  {C.CYAN}5{C.RST}) Замеры производительности (бенчмарк)")
        print(f"  {C.CYAN}6{C.RST}) Показать все сценарии подряд")
        print(f"  {C.RED}0{C.RST}) Выход")
        hdr("=" * 60)

        choice = input(f"{C.BOLD}Ваш выбор: {C.RST}").strip()

        if choice == '0':
            print(f"\n{C.DIM}Работа завершена.{C.RST}\n")
            break
        elif choice == '1':
            device, gateway = _connected_pair(pki)
            scenario_normal(device, gateway)
        elif choice == '2':
            device, gateway = _connected_pair(pki)
            scenario_tamper(device, gateway, Attacker())
        elif choice == '3':
            device, gateway = _connected_pair(pki)
            scenario_replay(device, gateway, Attacker())
        elif choice == '4':
            scenario_mitm(pki)
        elif choice == '5':
            run_benchmark()
            pause()
        elif choice == '6':
            device, gateway = _connected_pair(pki)
            scenario_normal(device, gateway)
            device, gateway = _connected_pair(pki)
            scenario_tamper(device, gateway, Attacker())
            device, gateway = _connected_pair(pki)
            scenario_replay(device, gateway, Attacker())
            scenario_mitm(pki)
            run_benchmark()
            pause()
        else:
            warn("Неверный выбор")


if __name__ == '__main__':
    try:
        menu()
    except KeyboardInterrupt:
        print(f"\n\n{C.YELLOW}Прервано пользователем.{C.RST}\n")
