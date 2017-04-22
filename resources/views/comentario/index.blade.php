<body>
@extends('layouts.app')
<div class="container">
    <h1>comentarios</h1>
     
    <h4><a href="{{ route('comentarios.create') }}">comentar</a></h4>
    <hr>
    <label><a href="{{ route('posts.index') }}">regresar a los avisos</a></label></h3>



    <div class="table-responsive">
        @if($cont)
          
                @foreach($cont as $row)
                    <tr>
                        <h3>comentario</h3>
                        <label>{{ $row->comen }}</label>
                        <p>comentado</p>
                        <label>{{ $row->created_at }}</label>
                        
                        
                        <td>
                         <a href="{{ route('comentarios.edit', $row->id) }}" class="btn btn-info">Editar</a>
                               <form action="{{ route('comentarios.destroy', $row->id) }}" method="post">
                                <input name="_method" type="hidden" value="DELETE">
                                <input type="hidden" name="_token" value="{{ csrf_token() }}">
                                <button type="submit" class="btn btn-danger">Eliminar</button>
                                 </form>

                                 <h3>
                        
                        </td>
                    </tr>
                </tbody>
                @endforeach
            </table>
               @endif

               
    </div>
</div>


</body>
 
</html>