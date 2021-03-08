<?php

namespace Metrogistics\AzureSocialite\Middleware;

use Closure;
use Illuminate\Auth\Middleware\Authenticate as BaseMiddleware;
use \Illuminate\Contracts\Auth\Authenticatable;

class Authenticate extends BaseMiddleware
{
    public function handle($request, Closure $next, ...$guards)
    {
        $azure_user = app('azure-user');

        $expires_in = $azure_user->get()->expiresIn;
        if ($expires_in < 0) {
            $azure_user->refreshAccessToken();
        }

        return parent::handle($request, $next, $guards);
    }

    protected $user;

    /**
     * Determine if the current user is authenticated.
     *
     * @return bool
     */
    public function check()
    {
        $user = app('azure-user')->get();

        return $user && $user->expiresIn > 0;
    }

    /**
     * Determine if the current user is a guest.
     *
     * @return bool
     */
    public function guest()
    {
        return !$this->check();
    }

    /**
     * Get the currently authenticated user.
     *
     * @return \Illuminate\Contracts\Auth\Authenticatable|null
     */
    public function user()
    {
        if ($this->user) {
            return $this->user;
        }

        $user_class = config('azure-oath.user_class');
        $field_name = config('azure-oath.user_id_field');
        $azure_user = app('azure-user')->get();

        $this->user = $user_class::where($field_name, $azure_user->id)->first();

        return $this->user;
    }

    /**
     * Get the ID for the currently authenticated user.
     *
     * @return int|null
     */
    public function id()
    {
        return $this->user() ? $this->user()->id : null;
    }

    /**
     * Validate a user's credentials.
     *
     * @param  array  $credentials
     * @return bool
     */
    public function validate(array $credentials = [])
    {
        // This is handles by SSO

        return true;
    }

    /**
     * Set the current user.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $user
     * @return void
     */
    public function setUser(Authenticatable $user)
    {
        $this->user = $user;
    }
}
