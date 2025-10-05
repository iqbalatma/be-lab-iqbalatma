<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Http\Requests\Auth\AuthenticateRequest;
use Illuminate\Support\Facades\Auth;
use Iqbalatma\LaravelUtils\APIResponse;

class AuthenticateController extends Controller
{
    public function __construct()
    {
        $this->responseMessages = [
            "authenticate" => "Authenticate successfully.",
            "logout" => "Logout successfully.",
            "refresh" => "Refresh successfully.",
        ];
    }

    /**
     * @param AuthenticateRequest $request
     * @return APIResponse
     */
    public function authenticate(AuthenticateRequest $request): APIResponse
    {
        $credentials = request(['username', 'password']);
        if (!$token = Auth::attempt($credentials)) {
            return new APIResponse(
                [
                    'error' => 'Unauthorized'
                ],
                "Invalid credentials."
            );
        }

        return $this->respondWithToken($token);
    }

    /**
     * @return APIResponse
     */
    public function logout(): APIResponse
    {
        auth()->logout();

        return new APIResponse(
            null,
            'Successfully logged out'
        );
    }

    /**
     * @return APIResponse
     */
    public function refresh(): APIResponse
    {
        return $this->respondWithToken(auth()->refresh());
    }

    protected function respondWithToken($token): APIResponse
    {
        ddapi($token);
        return new APIResponse(
            [
                'access_token' => $token,
                'token_type' => 'bearer',
                'expires_in' => auth()->factory()->getTTL() * 60
            ],
            "Generate token successfully.",
        );
    }
}
