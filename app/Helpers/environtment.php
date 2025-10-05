<?php

if (!function_exists('isProduction')) {

    /**
     * @return bool
     */
    function isProduction(): bool
    {
        return config("app.env") === \App\Enums\Environment::production->name;
    }
}

if (!function_exists('isStaging')) {

    /**
     * @return bool
     */
    function isStaging(): bool
    {
        return config("app.env") === \App\Enums\Environment::staging->name;
    }
}

if (!function_exists('isNonProduction')) {

    /**
     * @return bool
     */
    function isNonProduction(): bool
    {
        return config("app.env") !== \App\Enums\Environment::production->name;
    }
}

if (!function_exists('isNonStaging')) {

    /**
     * @return bool
     */
    function isNonStaging(): bool
    {
        return config("app.env") !== \App\Enums\Environment::staging->name;
    }
}
