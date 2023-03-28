<?php
namespace CarloNicora\Minimalism\Services\OAuthClient;

use CarloNicora\Minimalism\Abstracts\AbstractService;
use Exception;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;

class OAuthClient extends AbstractService
{
    /** @var array|null  */
    private ?array $token=null;

    /**
     * @param string $MINIMALISM_SERVICE_OAUTH_KEY
     */
    public function __construct(
        private readonly string $MINIMALISM_SERVICE_OAUTH_KEY,
    )
    {
    }

    /**
     * @return void
     */
    public function initialise(
    ): void
    {
        parent::initialise();

        $headers = getallheaders();
        $bearer = $headers['Authorization'] ?? null;
        if ($bearer !== null) {
            [, $token] = explode(' ', $bearer);
            if (!empty($token)){
                try {
                    $data = JWT::decode($token, new Key($this->MINIMALISM_SERVICE_OAUTH_KEY, 'RS256'));
                    $this->token = (array)$data;
                } catch (Exception) {
                    $this->token = null;
                }

                if ($this->token['expiration'] !== null && $this->token['expiration'] > time()) {
                    $this->token = null;
                }
            }
        }
    }

    public function isTokenValid(
    ): bool {
        return $this->token !== null;
    }

    /**
     * @return int
     */
    public function getUserId(): int {
        return $this->token['userId'];
    }

    /**
     * @return bool
     */
    public function isRegisteredUser(): bool {
        return $this->token['isUser'];
    }
}

// @codeCoverageIgnoreStart
if (! function_exists('getallheaders')) {
    // @codeCoverageIgnoreEnd
    function getallheaders(): array
    {
        $headers = [];
        foreach ($_SERVER ?? [] as $name => $value) {
            if (str_starts_with($name, 'HTTP_')) {
                $headers[str_replace(' ', '-', ucwords(strtolower(str_replace('_', ' ', substr($name, 5)))))] = $value;
            }
        }
        return $headers;
    }
    // @codeCoverageIgnoreStart
}
// @codeCoverageIgnoreEnd