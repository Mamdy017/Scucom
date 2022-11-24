package com.bezkoder.springjwt.security.services;


        import com.bezkoder.springjwt.models.User;

        import java.util.List;

public interface CrudService {

    String Supprimer(Long id_users);  // LA METHODE PERMETTANT DE SUPPRIMER UN COLLABORATEUR

    String Modifier(User users);   // LA METHODE PERMETTANT DE MODIFIER UN COLLABORATEUR

    List<User> Afficher();       // LA METHODE PERMETTANT D'AFFICHER UN COLLABORATEUR

}