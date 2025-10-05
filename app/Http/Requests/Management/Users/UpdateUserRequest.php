<?php

namespace App\Http\Requests\Management\Users;

use App\Enums\Table;
use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Validation\Rule;

class UpdateUserRequest extends FormRequest
{
    /**
     * Determine if the user is authorized to make this request.
     */
    public function authorize(): bool
    {
        return true;
    }

    /**
     * Get the validation rules that apply to the request.
     *
     * @return array<string, \Illuminate\Contracts\Validation\ValidationRule|array<mixed>|string>
     */
    public function rules(): array
    {
        return [
            "first_name" => "required|max:128",
            "last_name" => "nullable|max:128",
            "email" => ["required", "email", "max:128", Rule::unique(Table::users->name, "email")->ignore($this->id)],
            "username" => ["required","max:128", Rule::unique(Table::users->name, "username")->ignore($this->id)],
            "role_ids" => "array|nullable",
            "role_ids.*" => ["uuid", Rule::exists(Table::roles->name, "id")],
        ];
    }
}
