package com.bezkoder.springjwt.controllers;

        import com.bezkoder.springjwt.models.User;
        import com.bezkoder.springjwt.security.services.CrudService;
        import org.springframework.beans.factory.annotation.Autowired;
        import org.springframework.security.access.prepost.PreAuthorize;
        import org.springframework.web.bind.annotation.*;

        import java.util.List;

@RestController
@RequestMapping("/users")
public class CrudController {

    @Autowired
    private CrudService crudService;


    // µµµµµµµµµµµµµµµµµµµµµµµµµµµµµµµµµµµµµµµµµµµµµµµµµµ

    @PreAuthorize("hasRole('USER') or hasRole('MODERATOR') or hasRole('ADMIN')")
    @GetMapping("/afficher")
    public  List<User> AfficherUsers(){
        return crudService.Afficher();
    }

    // µµµµµµµµµµµµµµµµµµµµµµµµµµµµµµµµµµµµµµµµµµµµµµµµµµ   MODIFIER
    @PreAuthorize("hasRole('ADMIN')")
    @PutMapping({"/modifier"})
    public String ModierUser(@RequestBody User users){

        crudService.Modifier(users);
        return "Modification reussie avec succès";
    }

    @PreAuthorize("hasRole('ADMIN')")
    @DeleteMapping("/Supprimer/{id_users}")
    public String Supprimer(@PathVariable("id_users") Long id_users){
        crudService.Supprimer(id_users);
        return "Suppression reussie";
    }




}