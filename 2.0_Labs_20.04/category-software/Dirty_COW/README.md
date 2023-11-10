
## [Dirty-COW Attack Lab](https://seedsecuritylabs.org/Labs_20.04/Software/Dirty_COW/)

#### 2 Task 1: Modify a Dummy Read-Only File

## 2.1 Create a Dummy File

![](image.png)

## 2.2 Set Up the Memory Mapping Thread

- Downloaded the `cow_attack.c` from the Labsetup.zip file.

## 2.3 Set Up the `write` Thread

## 2.4 The `madvise` Thread

## 2.5 Launch the Attack

```sh
gcc cow_attack.c -lpthread
a.out
```

![](image-1.png)

#### 3 Task 2: Modify the Password File to Gain the Root Privilege

- Adding a new user account called `charlie`.

```sh
sudo adduser charlie
grep charlie /etc/passwd
```

![](image-2.png)

- Take a backup of the `/etc/passwd`.

![](image-3.png)

- Edit the `cow_attack.c` as shown in below screenshot.

![](image-8.png)

- Edit the `/zzz` to `/etc/passwd`

![](image-5.png)

- Updated the `222222` to `x:1001`

![](image-6.png)

- Updated the `******` to `x:0000`

![](image-7.png)

- Compiled and Verified that `charlie`'s UID is now 0.

![](image-4.png)
