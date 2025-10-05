<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Http\Requests\Auth\AuthenticateRequest;
use App\Http\ResponseCode;
use App\Models\User;
use Illuminate\Http\JsonResponse;
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
     * @return JsonResponse
     */
    public function authenticate(AuthenticateRequest $request): JsonResponse
    {
        $credentials = request(['username', 'password']);
        if (!$token = Auth::attempt($credentials)) {
            return response()->json(
                ["message" => "Invalid credentials."]
            );
        }

        /** @var User $user */
        $user = Auth::user();
        return response()->json(
            [
                "code" => ResponseCode::SUCCESS()->name,
                "message" => "Logged in successfully.",
                "timestamp" => now(),
                "payload" => [
                    "data" => [
                        "id" => $user->id,
                        "username" => $user->username,
                        "first_name" => $user->first_name,
                        "last_name" => $user->last_name,
                        "email" => $user->email,
                        "access_token" => Auth::getAccessToken(),
                    ],
                ],
            ]
        )
            ->withCookie(getCreatedCookieAccessTokenVerifier(Auth::getAccessTokenVerifier()))
            ->withCookie(getCreatedCookieRefreshToken(Auth::getRefreshToken()));
    }

    /**
     * @return APIResponse
     */
    public function logout(): APIResponse
    {
        Auth::logout();

        return new APIResponse(
            null,
            'Successfully logged out'
        );
    }

    /**
     * @return JsonResponse
     */
    public function refresh(): JsonResponse
    {
        Auth::refreshToken(Auth::user());

        /** @var User $user */
        $user = Auth::user();
        return response()->json(
            [
                "code" => ResponseCode::SUCCESS()->name,
                "message" => "Logged in successfully.",
                "timestamp" => now(),
                "payload" => [
                    "data" => [
                        "id" => $user->id,
                        "username" => $user->username,
                        "first_name" => $user->first_name,
                        "last_name" => $user->last_name,
                        "email" => $user->email,
                        "access_token" => Auth::getAccessToken()
                    ],
                ],
            ]
        )
            ->withCookie(getCreatedCookieAccessTokenVerifier(Auth::getAccessTokenVerifier()))
            ->withCookie(getCreatedCookieRefreshToken(Auth::getRefreshToken()));
    }
}
