<?php

use Illuminate\Support\Facades\Route;

Route::get('/', function () {
    return view('welcome');
});

Route::get('/dashboard', function () {
    return view('dashboard');
});

Route::get('/login', function () {
    return view('auth.login');
});

Route::get('/register', function () {
    return view('auth.register');
});

Route::get('/history', function () {
    return view('history');
});

Route::get('/attacks', function () {
    return view('attacks');
});

Route::get('/datasets', function () {
    return view('datasets');
});

Route::get('/detect', function () {
    return view('detect.index');
});

Route::get('/scan', function () {
    return view('scan.index');
});
