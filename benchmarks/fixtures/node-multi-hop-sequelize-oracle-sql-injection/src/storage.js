import { DataTypes, Sequelize } from "sequelize";

const database = new Sequelize("students", "application", "password", {
  dialect: "oracle",
  logging: false,
});
const Student = database.define(
  "Student",
  { firstName: DataTypes.STRING },
  { tableName: "Students", timestamps: false },
);

export async function findStudent(firstName) {
  return Student.findOne({ where: { firstName } });
}
