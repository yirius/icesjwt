<?php

namespace icesjwt;

/**
 * JSON Web Token For Thinkphp
 */
class Jwt
{

    /**
     * 当我们需要进行时间的判断的时候, 可能会出现http请求的延时等问题, 需要有一个富裕时间
     */
    public static $restway = 0;

    /**
     * 时间戳, 生成的时候和计算的时候都需要使用, 为了防止出现时间误差
     * @type null
     */
    public static $timestamp = null;

    public static $algs_can_use = [
        'HS256' => ['hash_hmac', 'SHA256'],
        'HS512' => ['hash_hmac', 'SHA512'],
        'HS384' => ['hash_hmac', 'SHA384'],
        'RS256' => ['openssl', 'SHA256'],
        'RS384' => ['openssl', 'SHA384'],
        'RS512' => ['openssl', 'SHA512']
    ];

    /**
     * @title 开始对jwt进行加密
     * @description
     * @createtime: 2018/6/27 16:40
     * @param array|string $payload
     * @param string $key
     * @param string $alg
     * @param string $keyId
     * @param array $head
     * @return string
     */
    public static function encode($payload, $key, $alg = 'HS256', $keyId = null, $head = null)
    {
        /**
         * 拼装header
         */
        $header = ['typ' => 'JWT', 'alg' => $alg];
        if ($keyId !== null) {
            $header['kid'] = $keyId;
        }
        /**
         * 如果给了head, 就去拼装一下
         */
        if ( isset($head) && is_array($head) ) {
            $header = array_merge($head, $header);
        }
        /**
         * 开始对jwt进行封装
         */
        $segments = [];
        $segments[] = static::urlsafeB64Encode(static::jsonEncode($header));
        $segments[] = static::urlsafeB64Encode(static::jsonEncode($payload));
        $signing_input = implode('.', $segments);

        $signature = static::sign($signing_input, $key, $alg);
        $segments[] = static::urlsafeB64Encode($signature);

        return implode('.', $segments);
    }

    /**
     * @title 对jwt生成的base64进行解码
     * @description
     * @createtime: 2018/6/27 20:31
     * @param string $jwt
     * @param string|array $key
     * @param array $allowed_algs
     * @return object
     */
    public static function decode($jwt, $key, array $allowed_algs = [])
    {
        $timestamp = is_null(static::$timestamp) ? time() : static::$timestamp;

        if (empty($key)) {
            throw new \InvalidArgumentException('必须要传入一个加密用的key值');
        }
        /**
         * 判断是不是header.payload.signature
         */
        $hps = explode('.', $jwt);
        if (count($hps) != 3) {
            throw new \UnexpectedValueException('传入的jwt错误');
        }
        list($headb64, $bodyb64, $cryptob64) = $hps;
        /**
         * 列出来之后,开始判断
         */
        if (null === ($header = static::jsonDecode(static::urlsafeB64Decode($headb64)))) {
            throw new \UnexpectedValueException('jwt的header加密解析失败');
        }
        if (null === $payload = static::jsonDecode(static::urlsafeB64Decode($bodyb64))) {
            throw new \UnexpectedValueException('jwt的body解析失败');
        }
        if (false === ($sig = static::urlsafeB64Decode($cryptob64))) {
            throw new \UnexpectedValueException('jwt的签名参数解析失败');
        }
        /**
         * 判断加密方式
         */
        if (empty($header->alg)) {
            throw new \UnexpectedValueException('jwt的头部没有指定加密方式');
        }
        if (empty(static::$algs_can_use[$header->alg])) {
            throw new \UnexpectedValueException('加密方式未在指定方式中');
        }
        if (!in_array($header->alg, $allowed_algs) && !empty($allowed_algs)) {
            throw new \UnexpectedValueException('加密方式未在允许方式内');
        }
        /**
         * 判断是否存在指定的keyid, 存在的话就用这个key
         */
        if (is_array($key) || $key instanceof \ArrayAccess) {
            if (isset($header->kid)) {
                if (!isset($key[$header->kid])) {
                    throw new \UnexpectedValueException('kid 代指keyId 未在指定key中给定, 但加密时指定该参数');
                }
                $key = $key[$header->kid];
            } else {
                throw new \UnexpectedValueException('kid 是空的, 无法使用来解密');
            }
        }

        /**
         * 开始检查加密
         */
        if (!static::verify($headb64.".".$bodyb64, $sig, $key, $header->alg)) {
            throw new SignatureException('加密方式校验失败');
        }

        /**
         * nbf指定的是jwt的生效时间, not before time
         */
        if (isset($payload->nbf) && $payload->nbf > ($timestamp + static::$restway)) {
            throw new BeforeValidException(
                '未到jwt生效时间: ' . date(\DateTime::ISO8601, $payload->nbf)
            );
        }

        /**
         * iat是用来检查jwt的创建时间
         */
        if (isset($payload->iat) && $payload->iat > ($timestamp + static::$restway)) {
            throw new BeforeValidException(
                'jwt创建时间错误:' . date(\DateTime::ISO8601, $payload->iat)
            );
        }

        /**
         * 判断是否已经过期了
         */
        if (isset($payload->exp) && ($timestamp - static::$restway) >= $payload->exp) {
            throw new ExpiredException('Expired token');
        }

        return $payload;
    }

    /**
     * @title 用指定方式和key签名
     * @description
     * @createtime: 2018/6/27 23:38
     * @param $msg
     * @param $key
     * @param string $alg
     * @return string
     */
    public static function sign($msg, $key, $alg = 'HS256')
    {
        if (empty(static::$algs_can_use[$alg])) {
            throw new \DomainException('签名方式不在指定几种内');
        }
        list($function, $algorithm) = static::$algs_can_use[$alg];
        switch($function) {
            case 'hash_hmac':
                return hash_hmac($algorithm, $msg, $key, true);
            case 'openssl':
                $signature = '';
                $success = openssl_sign($msg, $signature, $key, $algorithm);
                if (!$success) {
                    throw new \DomainException("OpenSSL无法用来签名,请检查是否存在");
                } else {
                    return $signature;
                }
        }
    }

    /**
     * Verify a signature with the message, key and method. Not all methods
     */
    private static function verify($msg, $signature, $key, $alg)
    {
        if (empty(static::$algs_can_use[$alg])) {
            throw new \DomainException('加密方式未在指定方式中');
        }

        list($function, $algorithm) = static::$algs_can_use[$alg];
        switch($function) {
            case 'openssl':
                $success = openssl_verify($msg, $signature, $key, $algorithm);
                if ($success === 1) {
                    return true;
                } elseif ($success === 0) {
                    return false;
                }
                // returns 1 on success, 0 on failure, -1 on error.
                throw new \DomainException(
                    'OpenSSL error: ' . openssl_error_string()
                );
            case 'hash_hmac':
            default:
                $hash = hash_hmac($algorithm, $msg, $key, true);
                if (function_exists('hash_equals')) {
                    return hash_equals($signature, $hash);
                }
                $len = min(static::safeStrlen($signature), static::safeStrlen($hash));

                $status = 0;
                for ($i = 0; $i < $len; $i++) {
                    $status |= (ord($signature[$i]) ^ ord($hash[$i]));
                }
                $status |= (static::safeStrlen($signature) ^ static::safeStrlen($hash));

                return ($status === 0);
        }
    }

    /**
     * @title 将json转换成array
     * @description
     * @createtime: 2018/6/27 23:46
     * @param $input
     * @return mixed
     */
    public static function jsonDecode($input)
    {
        $obj = json_decode($input, false, 512, JSON_BIGINT_AS_STRING);

        if (function_exists('json_last_error') && $errno = json_last_error()) {
            static::handleJsonError($errno);
        } elseif ($obj === null && $input !== 'null') {
            throw new \DomainException('输入了一个空值');
        }
        return $obj;
    }

    /**
     * @title jsonEncode
     * @description
     * @createtime: 2018/6/27 21:55
     * @param $input
     * @return string
     */
    public static function jsonEncode($input)
    {
        $json = json_encode($input);
        if (function_exists('json_last_error') && $errno = json_last_error()) {
            static::handleJsonError($errno);
        } elseif ($json === 'null' && $input !== null) {
            throw new \DomainException('输入了一个空值');
        }
        return $json;
    }

    /**
     * @title 安全的base64decode
     * @description
     * @createtime: ct
     * @param $input
     * @return string
     */
    public static function urlsafeB64Decode($input)
    {
        $remainder = strlen($input) % 4;
        if ($remainder) {
            $padlen = 4 - $remainder;
            $input .= str_repeat('=', $padlen);
        }
        return base64_decode(strtr($input, '-_', '+/'));
    }

    /**
     * @title 安全的base64方法
     * @description
     * @createtime: 2018/6/27 23:39
     * @param $input
     * @return mixed
     */
    public static function urlsafeB64Encode($input)
    {
        return str_replace('=', '', strtr(base64_encode($input), '+/', '-_'));
    }

    /**
     * Helper method to create a JSON error.
     *
     * @param int $errno An error number from json_last_error()
     *
     * @return void
     */
    private static function handleJsonError($errno)
    {
        $messages = array(
            JSON_ERROR_DEPTH => 'Maximum stack depth exceeded',
            JSON_ERROR_STATE_MISMATCH => 'Invalid or malformed JSON',
            JSON_ERROR_CTRL_CHAR => 'Unexpected control character found',
            JSON_ERROR_SYNTAX => 'Syntax error, malformed JSON',
            JSON_ERROR_UTF8 => 'Malformed UTF-8 characters' //PHP >= 5.3.3
        );
        throw new \DomainException(
            isset($messages[$errno])
            ? $messages[$errno]
            : 'Unknown JSON error: ' . $errno
        );
    }

    /**
     * Get the number of bytes in cryptographic strings.
     *
     * @param string
     *
     * @return int
     */
    private static function safeStrlen($str)
    {
        if (function_exists('mb_strlen')) {
            return mb_strlen($str, '8bit');
        }
        return strlen($str);
    }
}
