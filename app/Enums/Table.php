<?php

namespace App\Enums;

enum Table {
    case users;
    case sessions;
    case cache;
    case cache_locks;
    case jobs;
    case job_batches;
    case failed_jobs;
    case password_reset_tokens;
    case roles;
    case permissions;
    case model_has_permissions;
    case model_has_roles;
    case role_has_permissions;
}
