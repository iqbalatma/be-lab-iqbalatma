<?php

namespace App\Enums;

enum Role:string {

    case SUPER_ADMIN = "SUPER ADMIN";
    case ADMIN = "ADMIN";
    case GRAY_USER = "GRAY USER";
}
