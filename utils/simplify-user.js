const simplifyUser = (user) => {
  return {
    firstname: user.firstname,
    lastname: user.lastname,
    email: user.email,
    username: user.username,
    mobile: user.mobile,
    address: user.address,
  };
};

module.exports = simplifyUser;
