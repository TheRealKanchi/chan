<center>
<body>
<input type="hidden" name="_token" value="{{ csrf_token() }}">
@if(isset($post))




    <div class="form-group">
        <label for="name">Comentarios</label>
      
        <ol><textarea class="form-control" name="comen" rows="4" cols="50" value="{{ $comentario->comen }}"><?php echo $comentario->comen ?></textarea></ol>

      
    
       



    </div>

@else

    <div class="form-group">
    <label for="name">Comentarios</label>
     <ol><textarea class="form-control" name="comen" rows="4" cols="50"></textarea></ol>

   
                
              </div>
        

    

@endif
</body>
</center>