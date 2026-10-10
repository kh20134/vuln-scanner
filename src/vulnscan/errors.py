"""도구 전역 예외. CLI는 인가/범위 오류를 종료 코드 2로 돌린다."""


class VulnscanError(Exception):
    """복구 가능한 사용자 입력 또는 데이터 오류."""


class AuthorizationError(VulnscanError):
    """네트워크 점검 인가 확인이 없을 때."""


class ScopeError(VulnscanError):
    """대상 범위가 비었거나 허용 한도를 넘을 때."""


class DataError(VulnscanError):
    """원격 피드나 로컬 파일의 형식이 기대와 다를 때."""
