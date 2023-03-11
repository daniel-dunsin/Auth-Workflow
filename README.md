### Auth-Workflow
This is a backend service that provides endpoints for authentication of WebApps
The available endpoints are:

* Register User
* Login User with email verification 
* Password reset and Forgot password implementation
* Updating User details

#### Tech Stacks
* `Node JS`
* `Express JS`
* `Mongo DB`

#### Procedures
* To install dependencies run `npm install`
* Add the following in your .env: 
  `MONGOOSE_URI`, `JWT_SECRET`, `NODEMAILER_USERNAME`, `NODEMAILER_PASS`
* To start the server run `npm start`
