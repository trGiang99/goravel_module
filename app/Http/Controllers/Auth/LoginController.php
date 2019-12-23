<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Providers\RouteServiceProvider;
use Illuminate\Foundation\Auth\AuthenticatesUsers;
use Socialite;
use App\User;
use Illuminate\Support\Facades\Auth;

class LoginController extends Controller
{
    /*
    |--------------------------------------------------------------------------
    | Login Controller
    |--------------------------------------------------------------------------
    |
    | This controller handles authenticating users for the application and
    | redirecting them to your home screen. The controller uses a trait
    | to conveniently provide its functionality to your applications.
    |
    */

    use AuthenticatesUsers;

    /**
     * Where to redirect users after login.
     *
     * @var string
     */
    protected $redirectTo = RouteServiceProvider::HOME;

    /**
     * Create a new controller instance.
     *
     * @return void
     */
    public function __construct()
    {
        $this->middleware('guest')->except('logout');
    }

    public function redirectToGoogleProvider()
    {
        $parameters = [
            'access_type' => 'offline'
        ];
        return Socialite::driver('google')
                        ->scopes(["https://www.googleapis.com/auth/drive"])
                        ->with($parameters)
                        ->redirect();
    }

    public function handleProviderGoogleCallback()
    {
        $auth_user = Socialite::driver('google')->user();
        $data = [
            'token' => $auth_user->token,
            'expires_in' => $auth_user->expiresIn,
            'name' => $auth_user->name,
            'refresh_token' =>$auth_user->token
        ];

        if ($auth_user->refreshToken){
            $data['refresh_token'] = $auth_user->refreshToken;
        }

        $user = User::updateOrCreate(
            ['email' => $auth_user->email],
            $data
        );

        Auth::login($user, true);
        return redirect()->to('/');
    }
}
