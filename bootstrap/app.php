<?php

use App\Http\ResponseCode;
use Carbon\Carbon;
use Illuminate\Foundation\Application;
use Illuminate\Foundation\Configuration\Exceptions;
use Illuminate\Foundation\Configuration\Middleware;
use Iqbalatma\LaravelUtils\APIResponse;
use Symfony\Component\HttpFoundation\Response;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        web: __DIR__ . '/../routes/web.php',
        api: __DIR__ . '/../routes/api.php',
        commands: __DIR__ . '/../routes/console.php',
        health: '/up',
    )
    ->withMiddleware(function (Middleware $middleware) {
        $middleware->alias([
            'role' => \Spatie\Permission\Middleware\RoleMiddleware::class,
            'permission' => \Spatie\Permission\Middleware\PermissionMiddleware::class,
            'role_or_permission' => \Spatie\Permission\Middleware\RoleOrPermissionMiddleware::class,
        ]);
    })
    ->withExceptions(function (Exceptions $exceptions) {
        $exceptions->context(fn() => [
            "user_agent" => request()->userAgent(),
            "ip" => request()->ip(),
            "body" => request()->all(),
            "url" => request()->url(),
            "method" => request()->method(),
        ]);

        $exceptions->dontReport([
            \Iqbalatma\LaravelUtils\Exceptions\DumpAPIException::class,
            \Illuminate\Validation\ValidationException::class,
            \Symfony\Component\HttpKernel\Exception\NotFoundHttpException::class,
        ]);

        $exceptions->render(function (\Iqbalatma\LaravelJwtAuthentication\Exceptions\JWTUnauthenticatedUserException $e) {
            return new APIResponse(
                message: $e->getMessage(),
                responseCode: ResponseCode::ERR_UNAUTHENTICATED(),
                exception: $e
            );
        });

        $exceptions->render(using: function (
            \Firebase\JWT\ExpiredException|\Iqbalatma\LaravelJwtAuthentication\Exceptions\JWTInvalidTokenException|\Iqbalatma\LaravelJwtAuthentication\Exceptions\JWTInvalidIssuedUserAgent|\Iqbalatma\LaravelJwtAuthentication\Exceptions\JWTInvalidTokenTypeException|\Iqbalatma\LaravelJwtAuthentication\Exceptions\JWTUnauthenticatedUserException $e) {
            return new APIResponse(
                message: $e->getMessage(),
                responseCode: ResponseCode::ERR_UNAUTHENTICATED(),
                exception: $e
            );
        });

        $exceptions->render(function (\Iqbalatma\LaravelServiceRepo\Exceptions\EmptyDataException|\Spatie\Permission\Exceptions\RoleDoesNotExist $e) {
            return new APIResponse(
                message: $e->getMessage(),
                responseCode: ResponseCode::ERR_ENTITY_NOT_FOUND(),
                exception: $e
            );
        });


        $exceptions->render(function (\App\Exceptions\InvalidActionException|\Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException $e) {
            return new APIResponse(
                message: $e->getMessage(),
                responseCode: ResponseCode::ERR_FORBIDDEN(),
                exception: $e
            );
        });

        $exceptions->render(function (\Illuminate\Validation\ValidationException $e) {
            return new APIResponse(
                message: $e->getMessage(),
                responseCode: ResponseCode::ERR_VALIDATION(),
                errors: $e->errors(),
                exception: $e
            );
        });


        $exceptions->render(function (Error|Exception|RuntimeException|Throwable $e) {
            return new APIResponse(
                message: isProduction() ? "Something went wrong !" : $e->getMessage(),
                responseCode: ResponseCode::ERR_INTERNAL_SERVER_ERROR(),
                exception: $e
            );
//            return response()->json([
//                "rc" => ResponseCode::ERR_INTERNAL_SERVER_ERROR()->name,
//                "message" => isProduction() ? "Something went wrong !" : $e->getMessage(),
//                "timestamp" => Carbon::now(),
//                "payload" => null,
//            ], Response::HTTP_INTERNAL_SERVER_ERROR);
        });
    })->create();
