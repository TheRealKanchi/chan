@extends('layouts.app')
<body>
<div class="container">
    <h1>Temas</h1>
      @if(!Auth::guest())
    <h4><a href="{{ route('posts.create') }}">Crear Aviso</a></h4>
    <hr>
    @endif

    <div class="table-responsive">
        @if($data)
          
                @foreach($data as $row)
                    <tr>
                    <lavel><img src="image/{{$row->image}}"style="width:300px;"/>
                    <img src="image/{{$row->image2}}"style="width:300px;"/></lavel>
                         <h3>Nombre</h3>
                        <label>{{ $row->name }}</label>
                        <h3>Titulo</h3>
                        <label>{{ $row->title }}</label>
                        <h3>contenido</h3>
                        <label>{{ $row->body }}</label>
                        <p>creado</p>
                        <label>{{ $row->created_at }}</label>
                         
                         <ol><label><a href="{{ route('comentarios.index') }}">comentarios</a></label></ol>
                         </tr>
      <a href="{{ route('posts.edit', $row->id) }}" class="btn btn-info">Editar</a>
                               <form action="{{ route('posts.destroy', $row->id) }}" method="post">
                                <input name="_method" type="hidden" value="DELETE">
                                <input type="hidden" name="_token" value="{{ csrf_token() }}">
                                <button type="submit" class="btn btn-danger">Eliminar</button>
                                 </form>
                                 </td>
                    </tr>
                </tbody>
                @endforeach
            </table>
               @endif

</div>

 



</body>
