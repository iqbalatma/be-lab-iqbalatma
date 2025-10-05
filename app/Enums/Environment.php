<?php

namespace App\Enums;

enum Environment
{
    case production;
    case development;
    case staging;
    case local;
    case testing;
}
