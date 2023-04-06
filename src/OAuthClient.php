<?php
namespace CarloNicora\Minimalism\Services\OAuthClient;

use CarloNicora\Minimalism\Abstracts\AbstractService;
use CarloNicora\Minimalism\Factories\ServiceFactory;
use CarloNicora\Minimalism\Interfaces\Security\Interfaces\ApplicationInterface;
use CarloNicora\Minimalism\Interfaces\Security\Interfaces\SecurityInterface;
use Exception;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;

class OAuthClient extends AbstractService implements SecurityInterface
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
     * @param ServiceFactory $services
     * @return void
     */
    public function postIntialise(ServiceFactory $services,): void
    {
        parent::postIntialise($services);

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

                if ($this->token['expiration'] !== null && $this->token['expiration'] < time()) {
                    $this->token = null;
                }
            }
        }
    }

    /**
     * @return string|null
     */
    public static function getBaseInterface(): ?string
    {
        return SecurityInterface::class;
    }

    /**
     * @return int|null
     */
    public function getUserId(): ?int {
        return $this->token['userId'];
    }

    /**
     * @return bool|null
     */
    public function isUser(): ?bool {
        return $this->token['isUser'];
    }

    /**
     * @return ApplicationInterface|null
     */
    public function getApp(
    ): ?ApplicationInterface {
        return null;
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