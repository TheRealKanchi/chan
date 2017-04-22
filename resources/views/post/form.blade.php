
<center>
<body>
<input type="hidden" name="_token2" value="{{ csrf_token() }}">
@if(isset($post))



 <div class="form-group">
        <label for="name">Nombre</label>
        <ol><input type="text" name="name" class="form-control" placeholder="Nombre" value="{{ $post->name }}">
        </ol>
    </div>
    <div class="form-group">
        <label for="name">titulo</label>
        <ol><input type="text" name="title" class="form-control" placeholder="titulo" value="{{ $post->title }}">
   </ol> </div>
    <div class="form-group">
        <label for="name">Comentarios</label>
      
        <ol><textarea class="form-control" name="body" rows="4" cols="50" value="{{ $post->body }}"><?php echo $post->body ?></textarea></ol>

      
            <label class="col-md-4 control-label">Foto</label>
              <input type="file" class="form-control" name="image" value="{{ $post->image }}" >

               
            <label class="col-md-4 control-label">Foto</label>
              <input type="file" class="form-control" name="image2" vlue ="{{ $post->image2 }}">    
       



    </div>

@else
<div class="form-group">
   <label for="name">nombre</label>
        <ol><input type="text" name="name" class="form-control" placeholder="Nombre">
    </ol></div>


    <div class="form-group">
        <label for="name">Titulo</label>
        <ol><input type="text" name="title" class="form-control" placeholder="Titulo">
    </ol>
    </div>
    <div class="form-group">
    <label for="name">Comentarios</label>
     <ol><textarea class="form-control" name="body" rows="4" cols="50"></textarea></ol>

     <input type="hidden" name="_token" value="{{ csrf_token() }}">
            <label class="col-md-4 control-label">Foto</label>
              <input type="file" class="form-control" name="image" >



              <input type="hidden" name="_token" value="{{ csrf_token() }}">
            <label class="col-md-4 control-label">Foto</label>
              <input type="file" class="form-control" name="image2" >
                
              </div>
        
</div>
    

@endif
</body>
</center>