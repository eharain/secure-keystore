<?php

declare(strict_types=1);

namespace TechStyle\SecureKeystore;

use RuntimeException;
use Throwable;

/**
 * Thrown by every operation in this package that can fail in a way the caller
 * might want to handle rather than merely report.
 *
 * openssl_decrypt returns false rather than throwing, which is the failure mode
 * this type exists to convert: a wrong user key becomes BAD_USER_KEY, naming the
 * store, rather than an empty string a caller might mistake for a value.
 */
final class KeystoreException extends RuntimeException
{
    /** A stable identifier from ErrorCodes. */
    private string $errorCode;

    public function __construct(string $errorCode, string $message, ?Throwable $previous = null)
    {
        parent::__construct($message, 0, $previous);
        $this->errorCode = $errorCode;
    }

    /**
     * The stable code. Named getErrorCode rather than getCode because
     * Exception::getCode is an int and cannot carry a string.
     */
    public function getErrorCode(): string
    {
        return $this->errorCode;
    }

    public function __toString(): string
    {
        return $this->errorCode . ': ' . $this->getMessage();
    }
}
