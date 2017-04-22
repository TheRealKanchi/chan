<?php

namespace App\Http\Controllers;

use App\Post;

use Illuminate\Http\Request;
use Auth;

use App\Http\Requests;
use Exception;

class PostController extends Controller
{
    private $path ='post';
protected $redirectTo = 'posts.create';

    public function __construct(){
        $this->middleware('auth');
    }

    public function index(){

        $data = Post::all();
        return view($this->path.'.index', compact('data'));
    }

    public function create(){


        
        return view($this->path.'.create');
    }

    public function store(Request $request){
        /*
         * Register user.
         * */
        try{
            $post = new Post();
            $post->name     = $request->name;
             $post->user_id=Auth::user()->id;
            $post->title   = $request->title;
            $post->body   = $request->body;
            $post->image = $request->image;
            $post->image2 = $request->image2;
           
            $post->save();

            return redirect()->route('posts.index');
        }
        catch(Exception $e){

            return "Fatal error - ".$e->getMessage();
        }
    }

    public function destroy($id){
        try{
            $post = Post::findOrFail($id);
            $post->delete();
            return redirect()->route('posts.index');
        } catch (Exception $e){

            return "Fatal error - ".$e->getMessage();
        }

    }

    public function edit($id){
        $post = Post::findOrFail($id);
        return view($this->path.'.edit', compact('post'));
    }

    public function update(Request $request, $id){

        $post = Post::findOrFail($id);
        $post->name     = $request->name;
        $post->user_id=Auth::user()->id;
        $post->title    = $request->title;
        $post->body    = $request->body;
        $post->image = $request->image;
        $post->image2 = $request->image2;
        $post->save();
        return redirect()->route('posts.index');
    }


      protected function validator(array $data)
    {
        return Validator::make($data, [
            'name' => 'required|max:255',
            'title' => 'required',
            'body' => 'required',
             'image' => 'required',
              'image2' => 'required',
        ]);
    }
}

