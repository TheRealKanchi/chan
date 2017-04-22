<?php

namespace App;

use Illuminate\Database\Eloquent\Model;

use Carbon\Carbon;


class Post extends Model
{
     protected $fillable = [
      'user_id', 'name', 'title', 'body', 'image','image2',
    ];


     public function user(){
    	return $this->belongsTo('App\User');
}


  public function setImageAttribute($image){
		$name = Carbon::now()->second.$image->getClientOriginalName();
		$this->attributes['image'] = $name;
		\Storage::disk('local')->put($name, \File::get($image));
	}


   public function setImage2Attribute($image2){
    $name2 = Carbon::now()->second.$image2->getClientOriginalName();
    $this->attributes['image2'] = $name2;
    \Storage::disk('local')->put($name2, \File::get($image2));
  }





}