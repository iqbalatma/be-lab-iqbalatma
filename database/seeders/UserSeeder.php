<?php

namespace Database\Seeders;

use App\Enums\Role;
use App\Models\User;
use Illuminate\Database\Seeder;

class UserSeeder extends Seeder
{
    public const array DATA = [
        [
            "id" => "0195c52b-a15e-72a9-9fa0-55075b292001",
            "first_name" => "iqbal",
            "last_name" => "atma muliawan",
            "username" => "iqbalatma",
            "email" => "iqbalatma@gmail.com",
            "password" => "admin",
        ]
    ];

    /**
     * Run the database seeds.
     */
    public function run(): void
    {
        foreach (self::DATA as $user) {
            $createdRole = User::query()->create($user);
            $createdRole->assignRole([Role::SUPER_ADMIN->value, Role::ADMIN->value]);
        }
    }
}
