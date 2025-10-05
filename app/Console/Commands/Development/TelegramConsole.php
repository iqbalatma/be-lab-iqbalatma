<?php

namespace App\Console\Commands\Development;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Iqbalatma\LaravelLogTelegramChannel\Services\TelegramHandler;

class TelegramConsole extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'dev:telegram';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Test telegram command';

    /**
     * Execute the console command.
     */
    public function handle()
    {
        $this->info("Telegram command started");
//        $url = config("log_telegram_channel.host") . "/" . config("log_telegram_channel.token") . "/sendMessage";
//        $response = Http::post($url, [
//            "text" => "test message",
//            "chat_id" => config("log_telegram_channel.channel_id"),
//            "parse_mode" => TelegramHandler::PARSE_MODE,
//        ]);

        Log::critical("This is critical");
    }
}
