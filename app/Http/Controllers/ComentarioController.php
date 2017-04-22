<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;

use App\Comentario;
use Auth;

use App\Http\Requests;
use Exception;

class ComentarioController extends Controller
{
     private $path ='comentario';


       public function __construct(){
        $this->middleware('auth');
    }
     
    public function index()
    {
         $cont = Comentario::all();
        return view($this->path.'.index', compact('cont'));
        
    }

   
    public function create()
    {
         return view($this->path.'.create');
    }

   
    public function store(Request $request)
    {
         try{
            $comentario = new Comentario();
            $comentario->comen     = $request->comen;
             $comentario->user_id=Auth::user()->id;
              $comentario->post_id=Auth::post()->id;
            $comentario->save();

            return redirect()->route('comentarios.index');
        }
        catch(Exception $e){

            return "Fatal error - ".$e->getMessage();
        }
    
    }

  
    public function show($id)
    {
        
    }

   
    public function edit($id)
    {
        $comentario = Comentario::findOrFail($id);
        return view($this->path.'.edit', compact('comentario'));
    }

  
    public function update(Request $request, $id)
    {
         $comentario = Comentario::findOrFail($id);
        $comentario->comen    = $request->comen;
        $comentario->user_id=Auth::user()->id;
        $comentario->post_id=Auth::post()->id;
        $comentario->save();
        return redirect()->route('comentarios.index');
    }

   
    public function destroy($id)
    {
           try{
            $comentario = Comentario::findOrFail($id);
            $comentario->delete();
            return redirect()->route('comentarios.index');
        } catch (Exception $e){

            return "Fatal error - ".$e->getMessage();
        }
    }
}
