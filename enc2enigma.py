import hashlib
import secrets
import sys
import random

# --- 1. 기본 설정: Base-28 문자 집합 ---
# 사용할 문자 집합 (f, a, s, d + 그리스 문자 24개 = 총 28개)
CHAR_SET = 'fasd' + 'αβγδεζηθικλμνξοπρστυφχψω'
# 문자 집합의 길이 (진법)
BASE = len(CHAR_SET)
# 문자를 숫자로 빠르게 변환하기 위한 맵 (dict)
CHAR_MAP = {char: i for i, char in enumerate(CHAR_SET)}


# --- 2. 기본 헬퍼 함수 ---

def get_sha256_key(session_key_str: str) -> bytes:
    """
    사용자 세션 키(문자열)를 256비트(32바이트) 해시 키로 변환합니다.
    """
    # 문자열을 바이트로 인코딩한 후 해시합니다.
    return hashlib.sha256(session_key_str.encode('utf-8')).digest()

def generate_random_session_key() -> str:
    """
    간단하고 안전한 랜덤 세션 키를 생성합니다.
    """
    # 16바이트 길이의 URL-safe한 랜덤 문자열 생성
    return secrets.token_urlsafe(16)


# --- 3. Base-28 인코딩/디코딩 함수 ---

def encode_to_custom_base(data_bytes: bytes) -> str:
    """
    XOR 연산된 바이트(0~255 숫자)를 
    Base-28 (f,a,s,d,그리스문자) 문자열로 변환합니다.
    """
    encoded_str = ""
    for byte in data_bytes:
        # 각 바이트(0~255)를 28진법 2자리로 표현합니다.
        # (28 * 28 = 784, 255보다 크므로 2자리로 충분)
        
        # 몫 (첫 번째 자리)
        char1_index = byte // BASE
        # 나머지 (두 번째 자리)
        char2_index = byte % BASE
        
        encoded_str += CHAR_SET[char1_index] + CHAR_SET[char2_index]
        
    return encoded_str


def decode_from_custom_base(encoded_str: str) -> bytes:
    """
    Base-28 (f,a,s,d,그리스문자) 문자열을
    원본 바이트(0~255 숫자)로 복원합니다.
    """
    decoded_bytes = bytearray()
    
    # 2글자씩 짝지어 읽어옵니다.
    if len(encoded_str) % 2 != 0:
        raise ValueError("암호문 길이가 올바르지 않습니다. (짝수여야 함)")
        
    for i in range(0, len(encoded_str), 2):
        char1 = encoded_str[i]
        char2 = encoded_str[i+1]
        
        # 맵을 이용해 숫자로 변환
        char1_index = CHAR_MAP.get(char1)
        char2_index = CHAR_MAP.get(char2)
        
        # 만약 CHAR_SET에 없는 문자가 들어오면 에러 발생
        if char1_index is None or char2_index is None:
             raise ValueError("암호문에 유효하지 않은 문자가 포함되어 있습니다.")

        # 28진법을 10진수로 복원 ( (첫째자리 * 28) + 둘째자리 )
        original_byte = (char1_index * BASE) + char2_index
        decoded_bytes.append(original_byte)
        
    return bytes(decoded_bytes)


# --- 4. 가상 애니그마 머신 로직 ---

class VirtualRotor:
    """
    애니그마의 로터(회전판)를 흉내 냅니다.
    0-255 바이트를 무작위로 섞은 표를 가집니다.
    """
    def __init__(self, seed: bytes):
        # 시드(seed)를 기반으로 재현 가능한 난수 생성
        r = random.Random()
        r.seed(seed)
        
        # 0~255 순서 리스트
        wiring = list(range(256))
        # 시드를 기반으로 리스트를 섞는다 (이것이 로터의 '배선'이 됨)
        r.shuffle(wiring)
        
        # 정방향 (Forward) 배선
        self.forward = wiring
        
        # 역방향 (Backward) 배선 (빠른 조회를 위해 미리 생성)
        self.backward = [0] * 256
        for i, val in enumerate(self.forward):
            self.backward[val] = i

    def pass_forward(self, byte_in: int, position: int) -> int:
        """정방향 통과 (입력 -> 로터 -> 출력)"""
        entry_point = (byte_in + position) % 256
        exit_val = self.forward[entry_point]
        return (exit_val - position + 256) % 256

    def pass_backward(self, byte_in: int, position: int) -> int:
        """역방향 통과 (반사판 -> 로터 -> 출력)"""
        entry_point = (byte_in + position) % 256
        exit_val = self.backward[entry_point]
        return (exit_val - position + 256) % 256

def create_plugboard(key_bytes: bytes) -> dict:
    """
    키의 일부를 사용해 10쌍의 바이트를 교환하는 플러그보드를 생성합니다.
    """
    plugboard = {}
    # 20바이트를 사용해 10쌍을 만듭니다.
    for i in range(0, 20, 2):
        b1 = key_bytes[i]
        b2 = key_bytes[i + 1]
        
        if b1 != b2 and b1 not in plugboard and b2 not in plugboard:
            plugboard[b1] = b2
            plugboard[b2] = b1
    return plugboard

def pass_plugboard(byte_in: int, plugboard: dict) -> int:
    """플러그보드를 통과합니다. 연결된 값이 있으면 교환합니다."""
    return plugboard.get(byte_in, byte_in)

def pass_reflector(byte_in: int) -> int:
    """
    반사판을 흉내 냅니다. (간단한 방식: 255 - byte)
    """
    return (255 - byte_in)

def enigma_stream_cipher(data_bytes: bytes, session_key_str: str) -> bytes:
    """
    세션 키로 가상 애니그마를 설정하고,
    매 바이트마다 다른 키를 생성하여 XOR 연산을 수행합니다.
    """
    
    # 1. 세션 키로 256비트(32바이트) 해시 생성
    key_bytes = get_sha256_key(session_key_str)
    
    # 2. 해시 값으로 "애니그마 머신" 설정
    plugboard = create_plugboard(key_bytes[0:20])
    rotor1 = VirtualRotor(seed=key_bytes[20:24])
    rotor2 = VirtualRotor(seed=key_bytes[24:28])
    rotor3 = VirtualRotor(seed=key_bytes[28:32])
    
    pos1, pos2, pos3 = 0, 0, 0
    result_bytes = bytearray()

    # 3. 데이터의 모든 바이트에 대해 반복
    for i in range(len(data_bytes)):
        
        # --- 키스트림 생성 시작 ---
        # A. 로터 회전
        pos1 = (pos1 + 1) % 256
        if pos1 == 0:
            pos2 = (pos2 + 1) % 256
            if pos2 == 0:
                pos3 = (pos3 + 1) % 256
        
        # B. 키 생성 입력값 (i % 256)
        key_gen_input = i % 256 
        
        # C. 가상 애니그마 통과
        b = key_gen_input
        b = pass_plugboard(b, plugboard)
        b = rotor1.pass_forward(b, pos1)
        b = rotor2.pass_forward(b, pos2)
        b = rotor3.pass_forward(b, pos3)
        b = pass_reflector(b)
        b = rotor3.pass_backward(b, pos3)
        b = rotor2.pass_backward(b, pos2)
        b = rotor1.pass_backward(b, pos1)
        b = pass_plugboard(b, plugboard)
        
        keystream_byte = b
        # --- 키스트림 생성 완료 ---

        # 4. 원본 데이터와 생성된 키스트림을 XOR 연산
        xor_byte = data_bytes[i] ^ keystream_byte
        result_bytes.append(xor_byte)
        
    return bytes(result_bytes)


# --- 5. 암호화/복호화 메인 함수 ---

def encrypt(plaintext_str: str, session_key_str: str) -> str:
    """
    암호화 전체 과정 (애니그마 키스트림 사용)
    """
    try:
        plain_bytes = plaintext_str.encode('utf-8')
        xor_bytes = enigma_stream_cipher(plain_bytes, session_key_str)
        encoded_str = encode_to_custom_base(xor_bytes)
        return encoded_str
    except Exception as e:
        # 일반적인 오류 처리
        raise RuntimeError(f"암호화 중 오류 발생: {e}")


def decrypt(encoded_str: str, session_key_str: str) -> str:
    """
    복호화 전체 과정 (암호화의 역순)
    """
    try:
        decoded_bytes = decode_from_custom_base(encoded_str)
        plain_bytes = enigma_stream_cipher(decoded_bytes, session_key_str)
        plaintext_str = plain_bytes.decode('utf-8')
        return plaintext_str
    except (ValueError, KeyError):
        # Base-28 디코딩 실패 (잘못된 문자, 짝수 길이 아님)
        raise ValueError("복호화 실패: 암호문 형식이 잘못되었습니다.")
    except UnicodeDecodeError:
        # UTF-8 디코딩 실패 (키가 다르거나 데이터 손상)
        raise ValueError("복호화 실패: 세션 키가 다르거나 암호문이 손상되었습니다.")
    except Exception as e:
        # 기타 오류
        raise RuntimeError(f"복호화 중 알 수 없는 오류: {e}")


# --- 6. 터미널 인터페이스 (메인 실행 부분) ---

def main():
    """
    터미널 인터페이스 메인 함수
    """
    print("===============================================")
    print("  myEnigma  ")
    print("===============================================")
    print(f"사용 가능 문자 ({BASE}개): {CHAR_SET}")
    
    while True:
        print("\n--- 메뉴 ---")
        print("[1] 새 세션 키 생성")
        print("[2] 메시지 암호화")
        print("[3] 메시지 복호화")
        print("[4] 종료")
        
        choice = input("선택: ").strip() # 입력값 앞뒤 공백 제거
        
        if choice == '1':
            new_key = generate_random_session_key()
            print(f"\n✨ 새 세션 키가 생성되었습니다!")
            print(f" > {new_key}")
            print("(이 키를 친구와 안전하게 공유하세요.)")
            
        elif choice == '2':
            try:
                plaintext = input("암호화할 원본 메시지: ")
                session_key = input("사용할 세션 키: ")
                
                if not plaintext or not session_key:
                    print("\n[!] 메시지와 세션 키를 모두 입력해야 합니다.")
                    continue

                encrypted_msg = encrypt(plaintext, session_key)
                
                print("\n🔒 암호화 완료:")
                print(encrypted_msg)
            except Exception as e:
                print(f"\n[오류] {e}")

        elif choice == '3':
            try:
                encoded_text = input("복호화할 암호문: ")
                session_key = input("세션 키: ")

                if not encoded_text or not session_key:
                    print("\n[!] 암호문과 세션 키를 모두 입력해야 합니다.")
                    continue
                
                decrypted_msg = decrypt(encoded_text, session_key)
                
                print("\n🔓 복호화 완료:")
                print(decrypted_msg)
            except Exception as e:
                print(f"\n[오류] {e}")

        elif choice == '4':
            print("\n프로그램을 종료합니다.")
            sys.exit()
            
        else:
            print("\n[!] 1, 2, 3, 4 중 하나를 입력하세요.")


# 스크립트가 직접 실행될 때만 main() 함수를 호출
if __name__ == "__main__":
    main()