import hashlib
import secrets
import sys

# 1. 사용할 문자 집합 정의 (f, a, s, d + 그리스 문자 24개 = 총 28개)
CHAR_SET = 'fasd' + 'αβγδεζηθικλμνξοπρστυφχψω'
# 2. 문자 집합의 길이 (진법)
BASE = len(CHAR_SET)
# 3. 문자를 숫자로 빠르게 변환하기 위한 맵 (dict)
CHAR_MAP = {char: i for i, char in enumerate(CHAR_SET)}


def get_sha256_key(session_key_str: str) -> bytes:
    """
    사용자 세션 키(문자열)를 256비트(32바이트) 해시 키로 변환합니다.
    """
    # 문자열을 바이트로 인코딩한 후 해시합니다.
    return hashlib.sha256(session_key_str.encode('utf-8')).digest()


def xor_cipher(data_bytes: bytes, key_bytes: bytes) -> bytes:
    """
    데이터와 키를 바이트 단위로 XOR 연산합니다.
    암호화/복호화에 동일하게 사용됩니다.
    """
    key_len = len(key_bytes)
    # 바이트 배열로 변환 (XOR 결과를 저장하기 위함)
    result = bytearray()
    
    for i, byte in enumerate(data_bytes):
        # 키를 순환하며(modulo) XOR 연산 수행
        xor_byte = byte ^ key_bytes[i % key_len]
        result.append(xor_byte)
        
    return bytes(result)


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
        char1_index = CHAR_MAP[char1]
        char2_index = CHAR_MAP[char2]
        
        # 28진법을 10진수로 복원 ( (첫째자리 * 28) + 둘째자리 )
        original_byte = (char1_index * BASE) + char2_index
        decoded_bytes.append(original_byte)
        
    return bytes(decoded_bytes)


# --- 메인 기능 함수 ---

def encrypt(plaintext_str: str, session_key_str: str) -> str:
    """
    암호화 전체 과정
    """
    # 1. 세션 키로 256비트 해시 키 생성
    key_bytes = get_sha256_key(session_key_str)
    # 2. 원본 문자열을 바이트로 변환 (UTF-8)
    plain_bytes = plaintext_str.encode('utf-8')
    # 3. XOR 암호화 수행
    xor_bytes = xor_cipher(plain_bytes, key_bytes)
    # 4. 암호화된 바이트를 f,a,s,d,그리스 문자로 부호화(인코딩)
    encoded_str = encode_to_custom_base(xor_bytes)
    
    return encoded_str


def decrypt(encoded_str: str, session_key_str: str) -> str:
    """
    복호화 전체 과정 (암호화의 역순)
    """
    # 1. 세션 키로 256비트 해시 키 생성 (암호화 때와 동일해야 함)
    key_bytes = get_sha256_key(session_key_str)
    # 2. f,a,s,d,그리스 문자를 바이트로 복원(디코딩)
    decoded_bytes = decode_from_custom_base(encoded_str)
    # 3. XOR 복호화 수행
    plain_bytes = xor_cipher(decoded_bytes, key_bytes)
    # 4. 복호화된 바이트를 원본 문자열로 변환 (UTF-8)
    plaintext_str = plain_bytes.decode('utf-8')
    
    return plaintext_str


def generate_random_session_key() -> str:
    """
    간단하고 안전한 랜덤 세션 키를 생성합니다.
    """
    # 16바이트 길이의 URL-safe한 랜덤 문자열 생성
    return secrets.token_urlsafe(16)


def main():
    """
    터미널 인터페이스 메인 함수
    """
    print("======================================")
    print("  나만의 비밀 세션 암호화 프로그램  ")
    print("======================================")
    print(f"사용 가능 문자: {CHAR_SET}")
    
    while True:
        print("\n--- 메뉴 ---")
        print("[1] 새 세션 키 생성")
        print("[2] 메시지 암호화")
        print("[3] 메시지 복호화")
        print("[4] 종료")
        
        choice = input("선택: ")
        
        if choice == '1':
            new_key = generate_random_session_key()
            print(f"\n✨ 새 세션 키가 생성되었습니다!")
            print(f" > {new_key}")
            print("(이 키를 친구와 안전하게 공유하세요.)")
            
        elif choice == '2':
            try:
                plaintext = input("암호화할 원본 메시지: ")
                session_key = input("사용할 세션 키: ")
                
                encrypted_msg = encrypt(plaintext, session_key)
                
                print("\n🔒 암호화 완료:")
                print(encrypted_msg)
            except Exception as e:
                print(f"\n[오류] 암호화 중 문제가 발생했습니다: {e}")

        elif choice == '3':
            try:
                encoded_text = input("복호화할 암호문: ")
                session_key = input("세션 키: ")
                
                decrypted_msg = decrypt(encoded_text, session_key)
                
                print("\n🔓 복호화 완료:")
                print(decrypted_msg)
            except (ValueError, KeyError):
                print("\n[오류] 복호화 실패! 암호문 형식이 잘못되었습니다.")
            except UnicodeDecodeError:
                print("\n[오류] 복호화 실패! 세션 키가 다르거나 암호문이 손상되었습니다.")
            except Exception as e:
                print(f"\n[오류] 알 수 없는 오류 발생: {e}")

        elif choice == '4':
            print("\n프로그램을 종료합니다.")
            sys.exit()
            
        else:
            print("\n[!] 1, 2, 3, 4 중 하나를 입력하세요.")


# 스크립트가 직접 실행될 때만 main() 함수를 호출
if __name__ == "__main__":
    main()