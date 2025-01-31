<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| is assigned the "api" middleware group. Enjoy building your API!
|
*/

Route::prefix('setup')->group(function () {
    
});

Route::prefix('location')->group(function () {
    Route::get('/country','API\LocationController@getCountry');
    Route::get('/country/{id}/states','API\LocationController@getStateByCountry');
    Route::get('/state/{id}/cities','API\LocationController@getCityByState');
});

Route::middleware('auth:sanctum')->prefix('setup')->group(function () {
    Route::get('/algolia-search-config','API\SetupController@algoliaSearchConfig')->name('setup.algolia.search.config');
    Route::post('/update-algolia-search-config', 'API\SetupController@updateAlgoliaSearchConfig')->name('setup.update.algolia.search.config');
});
