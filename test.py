# import dropbox

# dbx = dropbox.Dropbox('eCp2HTOUrNUAAAAAAAAAASLGV_nwg-uK-KcCXkZTWnT66l2rg9-W6CAGKZnMTiLI')

# result = dbx.files_get_temporary_link('/test.txt')

# print(result.link)
import yadisk
y = yadisk.YaDisk(token="AgAAAABITC7sAAav1g3D_G43akSwv85Xg-yPrCY")
# or
# y = yadisk.YaDisk("<application-id>", "<application-secret>", "<token>")
# Check if the token is valid
# y.upload("test.txt", "/destination.txt")
print(1)
print(y.get_download_link('/destination.txt'))
# Get disk information
print(y.get_disk_info())