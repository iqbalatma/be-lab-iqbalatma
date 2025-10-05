<?php

namespace App\Http;

use Symfony\Component\HttpFoundation\Response;

class ResponseCode extends \Iqbalatma\LaravelUtils\ResponseCode
{
    protected function mapHttpCode(): void
    {
        $this->httpCode = match ($this->name) {
            self::SUCCESS => Response::HTTP_OK,
            self::CREATED => Response::HTTP_CREATED,
            self::ERR_VALIDATION => Response::HTTP_UNPROCESSABLE_ENTITY,
            self::ERR_FORBIDDEN, self::ERR_UNAUTHORIZED => Response::HTTP_FORBIDDEN,
            self::ERR_UNAUTHENTICATED => Response::HTTP_UNAUTHORIZED,
            self::ERR_ENTITY_NOT_FOUND => Response::HTTP_NOT_FOUND,
            self::ERR_BAD_REQUEST, self::MISSING_REQUIRED_HEADER => Response::HTTP_BAD_REQUEST,
            default => Response::HTTP_INTERNAL_SERVER_ERROR,
        };
    }
}
