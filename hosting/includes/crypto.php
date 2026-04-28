<?php
declare(strict_types=1);

/**
 * Cifrado simétrico AES-256-CBC para API keys de proveedores externos.
 * La clave maestra se define en config.php y NUNCA debe ser commiteada.
 */

if (!defined('MASTER_ENCRYPTION_KEY')) {
    throw new RuntimeException('MASTER_ENCRYPTION_KEY no definida en config.php');
}

function encryptApiKey(string $plaintext): string {
    $cipher = 'aes-256-cbc';
    $ivLen = openssl_cipher_iv_length($cipher);
    $iv = random_bytes($ivLen);
    $key = hash('sha256', MASTER_ENCRYPTION_KEY, true);
    $ciphertext = openssl_encrypt($plaintext, $cipher, $key, OPENSSL_RAW_DATA, $iv);
    if ($ciphertext === false) {
        throw new RuntimeException('Cifrado falló');
    }
    return base64_encode($iv . $ciphertext);
}

function decryptApiKey(string $encoded): string {
    $cipher = 'aes-256-cbc';
    $data = base64_decode($encoded, true);
    if ($data === false) throw new RuntimeException('Base64 inválido');
    $ivLen = openssl_cipher_iv_length($cipher);
    $iv = substr($data, 0, $ivLen);
    $ciphertext = substr($data, $ivLen);
    $key = hash('sha256', MASTER_ENCRYPTION_KEY, true);
    $plaintext = openssl_decrypt($ciphertext, $cipher, $key, OPENSSL_RAW_DATA, $iv);
    if ($plaintext === false) {
        throw new RuntimeException('Descifrado falló');
    }
    return $plaintext;
}

function apiKeyHint(string $plaintext): string {
    $len = strlen($plaintext);
    if ($len <= 8) return str_repeat('*', $len);
    return substr($plaintext, 0, 4) . '...' . substr($plaintext, -4);
}
