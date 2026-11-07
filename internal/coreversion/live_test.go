package coreversion

import (
 "context"
 "os"
 "testing"
 "time"
)

func TestOfficialReleaseCatalogueLive(t *testing.T){
 if os.Getenv("XRAY_TEST_OFFICIAL_CATALOG")!="1"{t.Skip("set XRAY_TEST_OFFICIAL_CATALOG=1 to query official release metadata")}
 ctx,cancel:=context.WithTimeout(context.Background(),25*time.Second);defer cancel()
 result,err:=NewCatalog().List(ctx,false);if err!=nil{t.Fatal(err)}
 if result.Stale||len(result.Releases)==0||result.FetchedAt.IsZero(){t.Fatal("official catalogue did not produce a fresh selectable list")}
 t.Logf("official releases=%d, first tag=%s",len(result.Releases),result.Releases[0].Tag)
}
