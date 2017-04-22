@section('content')

  <td>
      <a href="{{ route('posts.edit', $row->id) }}" class="btn btn-info">Editar</a>
                               <form action="{{ route('posts.destroy', $row->id) }}" method="post">
                                <input name="_method" type="hidden" value="DELETE">
                                <input type="hidden" name="_token" value="{{ csrf_token() }}">
                                <button type="submit" class="btn btn-danger">Eliminar</button>
                                 </form>
                    
                        <label><a href="{{ route('comentarios.index') }}">comentarios</a></label></h3>

                        </td>

                        @endsection