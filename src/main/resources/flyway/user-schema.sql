CREATE TABLE "user" (
   id bigint NOT NULL,
   username varchar(200) NOT NULL,
   password text NOT NULL,
   name varchar(200) NOT NULL,
   registered_with varchar(255) NOT NULL,
   first_login boolean NOT NULL,
   picture text NOT NULL,
   authorities varchar(1000) NOT NULL,
   PRIMARY KEY (id)
);
