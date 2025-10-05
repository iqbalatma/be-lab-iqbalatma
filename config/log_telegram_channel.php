<?php

return [
    /*
    |--------------------------------------------------------------------------
    | Telegram Bot Host
    |--------------------------------------------------------------------------
    |
    | This is telegram bot host. You can find this host information at telegram
    | bot documentation https://core.telegram.org/bots/api
    |
    */
    "host" => env("LOG_TELEGRAM_HOST", "https://api.telegram.org"),


    /*
    |--------------------------------------------------------------------------
    | Telegram Bot Token
    |--------------------------------------------------------------------------
    |
    | This is token for authorization. You can get this token when create
    | telegram bot via BotFather. You need to add prefix bot on you generated
    | token. If your token like this 123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11
    | then you token value for this configuration would be
    | bot123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11
    |
    */
    "token" => env("LOG_TELEGRAM_TOKEN", null),


    /*
    |--------------------------------------------------------------------------
    | Telegram Channel Id
    |--------------------------------------------------------------------------
    |
    | This is channel id of target room chat channel. You can get this value
    | via username of the channel with format @channelusername. If your channel
    | is private, try to change channel into public and then send message via
    | postman to get response information of channel id. The value would be like
    | this -1002017173213. If you are using private channel, please use this id
    | format.
    |
    */
    "channel_id" => env("LOG_TELEGRAM_CHANNEL_ID", null),


    /*
    |--------------------------------------------------------------------------
    | Truncate Message
    |--------------------------------------------------------------------------
    |
    | When you send message via bot telegram, the message has length limit of
    | string. So you need to tell is the log message will be truncated, or
    | the message will send multiple times. If you set false, the message will
    | not truncated and send multiple times.
    |
    */
    "is_truncate_message" => env("LOG_TELEGRAM_IS_TRUNCATE_MESSAGE", false),



    /*
    |--------------------------------------------------------------------------
    | Fallback Channel
    |--------------------------------------------------------------------------
    |
    | There are conditions when this library got some failure and throw exception.
    | In this case, we will catch that exception and send log to this specific
    | channel to prevent infinity loop.
    |
    */
    "fallback_channel" => env("LOG_TELEGRAM_FALLBACK_CHANNEL", "single"),
];
