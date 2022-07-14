class MessageValidationException(Exception):
    def __init__(self, message):
        super().__init__(message)


class ActionExecutionException(Exception):
    def __init__(self, message):
        super().__init__(message)


class InitializationException(Exception):
    def __init__(self, message):
        super().__init__(message)

