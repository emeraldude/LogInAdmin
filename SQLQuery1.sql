--drop table Accounts

create table Accounts
(
	username varchar(16),
	salt nvarchar(max),
	password nvarchar(max),
	primary key(username)
)

select * from Accounts