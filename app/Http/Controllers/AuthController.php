<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Facades\Auth;

class AuthController extends Controller
{
    // User registration
    public function register(Request $request)
    {
        // Validate the incoming request
        $rules = [
            'name' => 'required',
            'email' => 'required|email|unique:users,email',
            'password' => 'required',
        ];

        $validator = Validator::make($request->all(), $rules);
        
        if ($validator->fails()) {
            return response()->json([
                'status' => false,
                'errors' => $validator->errors(),
            ], 422);
        }

        // Create the user
        $user = User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => Hash::make($request->password),
        ]);

        // Optionally, return the created user data
        return response()->json([
            'status' => true,
            'message' => 'User Registered Successfully',
            'user' => $user,
        ], 201);
    }

    // User login
    public function login(Request $request)
    {
        // Validate the incoming request
        $rules = [
            'email' => 'required|email',
            'password' => 'required',
        ];

        $validator = Validator::make($request->all(), $rules);

        if ($validator->fails()) {
            return response()->json([
                'status' => false,
                'message' => 'Invalid Credentials!',
                'errors' => $validator->errors()->all(),
            ], 401);
        }

        if (Auth::attempt(['email' => $request->email, 'password' => $request->password])) {
            // Authentication passed
            $user = Auth::user();
            $token = $user->createToken('auyh_token')->accessToken; // If using Passport

            return response()->json([
                'status' => true,
                'message' => 'User Logged In Successfully.',
                'user' => $user,
                'token' => $token,
            ], 200);
        }

        return response()->json([
            'status' => false,
            'message' => 'Invalid Credentials!',
        ], 401);
    }


    public function logout(Request $request)
    {
        $user = $request->user();
        $user->tokens()->delete();

        return response()->json([
            'status' => true,
            'message' => 'User Logged Out Successfully',
            'user' => $user,
        ], 200);
    }
}