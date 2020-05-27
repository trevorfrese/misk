package misk.crypto

import java.security.GeneralSecurityException

class InvalidEncryptionContextException : GeneralSecurityException {
  constructor(message: String) : super(message)
  constructor(message: String, throwable: Throwable) : super(message, throwable)
}
