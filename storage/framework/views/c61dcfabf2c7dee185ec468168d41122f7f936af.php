<center>
<body>
<input type="hidden" name="_token" value="<?php echo e(csrf_token()); ?>">
<?php if(isset($post)): ?>




    <div class="form-group">
        <label for="name">Comentarios</label>
      
        <ol><textarea class="form-control" name="comen" rows="4" cols="50" value="<?php echo e($comentario->comen); ?>"><?php echo $comentario->comen ?></textarea></ol>

      
    
       



    </div>

<?php else: ?>

    <div class="form-group">
    <label for="name">Comentarios</label>
     <ol><textarea class="form-control" name="comen" rows="4" cols="50"></textarea></ol>

   
                
              </div>
        

    

<?php endif; ?>
</body>
</center>