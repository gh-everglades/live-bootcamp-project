use auth_service::Application;

#[tokio::main]
async fn main() {
    //let app = Router::new()
    //    .nest_service("/", ServeDir::new("assets"))
    //    .route("/hello", get(hello_handler));

    // Here we are using ip 0.0.0.0 so the service is listening on all the configured network interfaces.
    // This is needed for Docker to work, which we will add later on.
    // See: https://stackoverflow.com/questions/39525820/docker-port-forwarding-not-working
    //let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    //println!("listening on {}", listener.local_addr().unwrap());

    //axum::serve(listener, app).await.unwrap();

    // -------------------------------------------------
    // Build and run the application
    let app = Application::build("0.0.0.0:3000")
        .await
        .expect("Failed to build app");

    app.run().await.expect("Failed to run app");
}
