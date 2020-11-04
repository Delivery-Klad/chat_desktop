import dropbox

dbx = dropbox.Dropbox('eCp2HTOUrNUAAAAAAAAAASLGV_nwg-uK-KcCXkZTWnT66l2rg9-W6CAGKZnMTiLI')

result = dbx.sharing_create_shared_link_with_settings('/test.txt')

print(result.url)
# import yadisk
# y = yadisk.YaDisk(token="AgAAAABITC7sAAav1g3D_G43akSwv85Xg-yPrCY")
# y.upload("test.txt", "/destination.txt")
# print(y.get_download_link('/destination.txt'))
# print(y.get_disk_info())