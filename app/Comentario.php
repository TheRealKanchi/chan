<?php

namespace App;

use Illuminate\Database\Eloquent\Model;

class Comentario extends Model
{
    protected $fillable = [
      'user_id', 'comen',
      ];


     public function user(){
    	return $this->belongsTo('App\User');
}
      
}

